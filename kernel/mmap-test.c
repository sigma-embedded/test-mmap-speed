/*	--*- c -*--
 * Copyright (C) 2017 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/dma-attrs.h>
#include <linux/dma-mapping.h>
#include <linux/ioctl.h>

#define MMAP_IOCTL_MODE_WRITEBACK	_IO('M', 0)
#define MMAP_IOCTL_MODE_WRITETHROUGH	_IO('M', 1)
#define MMAP_IOCTL_MODE_COHERENT	_IO('M', 2)
#define MMAP_IOCTL_MODE_WRITECOMBINE	_IO('M', 3)

struct mmap_dev {
	struct device		*dev;
	struct dma_attrs	attrs;
	struct mutex		lock;

	struct list_head	bufs;
	struct kref		kref;
};

struct mmap_buffer {
	dma_addr_t		addr;
	void *			mem;
	size_t			size;
	struct dma_attrs	attrs;
	struct list_head	head;
	struct mmap_dev		*mdev;
};

static int mmap_test_open(struct inode *ino, struct file *filp)
{
	struct miscdevice	*misc = filp->private_data;
	struct mmap_dev		*mdev;

	mdev = kzalloc(sizeof *mdev, GFP_KERNEL);
	if (!mdev)
		return -ENOMEM;

	mdev->dev = get_device(misc->this_device);
	init_dma_attrs(&mdev->attrs);
	mutex_init(&mdev->lock);
	kref_init(&mdev->kref);
	INIT_LIST_HEAD(&mdev->bufs);

	filp->private_data = mdev;

	return 0;
}

static void mmap_test_destroy(struct kref *kref)
{
	struct mmap_dev	*mdev = container_of(kref, struct mmap_dev, kref);

	mutex_lock(&mdev->lock);
	while (!list_empty(&mdev->bufs)) {
		struct mmap_buffer	*buf =
			list_last_entry(&mdev->bufs, struct mmap_buffer, head);

		list_del(&buf->head);
		mutex_unlock(&mdev->lock);

		dma_free_attrs(mdev->dev, buf->size, buf->mem,
			       buf->addr, &buf->attrs);

		kfree(buf);

		mutex_lock(&mdev->lock);
	}
	mutex_unlock(&mdev->lock);

	put_device(mdev->dev);

	kfree(mdev);
}

static int mmap_test_release(struct inode *ino, struct file *filp)
{
	struct mmap_dev		*mdev = filp->private_data;

	kref_put(&mdev->kref, mmap_test_destroy);

	return 0;
}

static void mmap_test_vm_open(struct vm_area_struct *vma)
{
	struct mmap_buffer	 *buf = vma->vm_private_data;

	kref_get(&buf->mdev->kref);
}

static void mmap_test_vm_close(struct vm_area_struct *vma)
{
	struct mmap_buffer	 *buf = vma->vm_private_data;

	kref_put(&buf->mdev->kref, mmap_test_destroy);
}

static struct vm_operations_struct const	mmap_test_vm_ops = {
	.open	= mmap_test_vm_open,
	.close	= mmap_test_vm_close,
};

static int mmap_test_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct mmap_dev		*mdev = filp->private_data;
	struct mmap_buffer	*buf;
	int			rc;

	buf = kmalloc(sizeof *buf, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&mdev->lock);
	buf->attrs = mdev->attrs;
	mutex_unlock(&mdev->lock);

	buf->mdev = mdev;
	buf->size = vma->vm_end - vma->vm_start;

	buf->mem = dma_alloc_attrs(mdev->dev, buf->size, &buf->addr, GFP_KERNEL,
				   &buf->attrs);
	if (!buf->mem) {
		rc = -ENOMEM;
		goto out;
	}

	printk("XXX: mmap: %x+%zd => %p\n", buf->addr, buf->size, buf->mem);

	rc = dma_mmap_attrs(mdev->dev, vma, buf->mem, buf->addr, buf->size,
			    &buf->attrs);
	if (rc < 0)
		goto out;

	vma->vm_flags		|= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data	= buf;
	vma->vm_ops		= &mmap_test_vm_ops;

	vma->vm_ops->open(vma);

	mutex_lock(&mdev->lock);
	list_add_tail(&buf->head, &mdev->bufs);
	mutex_unlock(&mdev->lock);

	rc = 0;
	buf = 0;

out:
	if (buf) {
		if (buf->mem)
			dma_free_attrs(mdev->dev, buf->size, buf->mem,
				       buf->addr, &buf->attrs);

		kfree(buf);
	}

	return rc;
}

static long mmap_test_ioctl(struct file *filp,
			    unsigned int cmd, unsigned long arg)
{
	struct mmap_dev		*mdev = filp->private_data;

	DEFINE_DMA_ATTRS(attrs);
	dma_set_attr(DMA_ATTR_NON_CONSISTENT, &attrs);
	dma_set_attr(DMA_ATTR_FORCE_CONTIGUOUS, &attrs);

	switch (cmd) {
	case MMAP_IOCTL_MODE_WRITEBACK:
		dma_set_attr(DMA_ATTR_WRITE_BACK, &attrs);
		break;

	case MMAP_IOCTL_MODE_WRITETHROUGH:
		dma_set_attr(DMA_ATTR_WRITE_THROUGH, &attrs);
		break;

	case MMAP_IOCTL_MODE_WRITECOMBINE:
		dma_set_attr(DMA_ATTR_WRITE_COMBINE, &attrs);
		break;

	case MMAP_IOCTL_MODE_COHERENT:
		break;

	default:
		return -ENOTTY;
	}

	mutex_lock(&mdev->lock);
	mdev->attrs = attrs;
	mutex_unlock(&mdev->lock);

	return 0;
}

static struct file_operations const	mmap_test_fops = {
	.open		= mmap_test_open,
	.release	= mmap_test_release,
	.mmap		= mmap_test_mmap,
	.unlocked_ioctl	= mmap_test_ioctl,
};

static struct miscdevice	mmap_test_parent_dev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "mmap-test",
	.fops		= &mmap_test_fops,
};

static int mmap_test_init(void)
{
	int	rc;
	struct device	*dev;

	rc = misc_register(&mmap_test_parent_dev);
	if (rc < 0)
		return rc;

	dev = mmap_test_parent_dev.this_device;
	dev->coherent_dma_mask = DMA_BIT_MASK(32);

	return rc;
}

static void mmap_test_exit(void)
{
	misc_deregister(&mmap_test_parent_dev);
}

module_init(mmap_test_init);
module_exit(mmap_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Enrico Scholz <enrico,scholz@sigma-chemnitz.de>");
