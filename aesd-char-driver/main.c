/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 * Few functions in this module are written by Vignesh Vadivel
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h> // file_operations
#include "aesd_ioctl.h"
#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Vignesh Vadivel");
MODULE_LICENSE("Dual BSD/GPL");

loff_t aesd_llseek(struct file *filp, loff_t off, int whence);
long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp){
  PDEBUG("open");
  filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
  return 0;
}

int aesd_release(struct inode *inode, struct file *filp){
  PDEBUG("release");
  return 0;
}


ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos){
  ssize_t bytesReadFromKernelSpace = 0;
  ssize_t bytesUnread = 0;
  struct aesd_buffer_entry *readDataNode; 
  ssize_t bytesReadToUserSpace = 0;
  int mutexLockReturn;

  if (filp == NULL || buf == NULL || f_pos == NULL){
    return -EFAULT;
  }

  PDEBUG("read %zu bytes with offset %lld", count, *f_pos);
  
  // Mutex Lock //
  mutexLockReturn = mutex_lock_interruptible(&((struct aesd_dev *)filp->private_data)->lock);
  if (mutexLockReturn){
    PDEBUG(KERN_ERR "Interruptible mutex lock is unsuccessful");
    return -ERESTARTSYS;
  }
  
  // Data read from kernel space //
  readDataNode = aesd_circular_buffer_find_entry_offset_for_fpos(&(((struct aesd_dev *)filp->private_data)->circle_buff), *f_pos, &bytesReadFromKernelSpace);
  if (readDataNode == NULL){
    PDEBUG(KERN_ERR "Data read from the buffer is unsuccessful");
    mutex_unlock(&(((struct aesd_dev *)filp->private_data)->lock));
    return bytesReadToUserSpace;
  }
  else{
    if (count > (readDataNode->size - bytesReadFromKernelSpace))
      count = readDataNode->size - bytesReadFromKernelSpace;
  }
  
  // Copy to user space buffer //
  bytesUnread = copy_to_user(buf, (readDataNode->buffptr + bytesReadFromKernelSpace), count);
  if (bytesUnread == 0){
    PDEBUG("All bytes are read from kernel space");
  }

  // Update actual number of bytes read //
  bytesReadToUserSpace = count - bytesUnread;
  *f_pos += bytesReadToUserSpace;

  // No return check for mutex unlock //
  mutex_unlock(&(((struct aesd_dev *)filp->private_data)->lock));
  return bytesReadToUserSpace;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos){
  struct aesd_dev *device;
  ssize_t bytesWrittenToKernelSpace = -ENOMEM;
  int mutexLockReturn;
  ssize_t bytesUnWritten = 0;
  const char *write_entry = NULL;

  if (filp == NULL || buf == NULL || f_pos == NULL)
    return -EFAULT;
  PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

  device = (struct aesd_dev *)filp->private_data;
  // Mutex Lock //
  mutexLockReturn = mutex_lock_interruptible(&(device->lock));
  if (mutexLockReturn){
    PDEBUG(KERN_ERR "Interruptible mutex lock is unsuccessful");
    return -ERESTARTSYS;
  }
  
  // if  buffer size is zero, then allocate the buffer using kmalloc, store address in buffptr
  if (device->circle_buff_entry.size == 0){
    PDEBUG("Allocate Buffer");
    device->circle_buff_entry.buffptr = kmalloc(count, GFP_KERNEL);
    if (device->circle_buff_entry.buffptr == NULL){
      PDEBUG("Memory Allocation failed");
      // No return check for mutex unlock //
      mutex_unlock(&device->lock);
      return bytesWrittenToKernelSpace;
    }
  }
  else{
    PDEBUG("Reallocate Buffer");
    device->circle_buff_entry.buffptr = krealloc(device->circle_buff_entry.buffptr, (device->circle_buff_entry.size + count), GFP_KERNEL);
    if (device->circle_buff_entry.buffptr == NULL){
      PDEBUG("krealloc error");
      // No return check for mutex unlock //
      mutex_unlock(&device->lock);
      return bytesWrittenToKernelSpace;
    }
  }
  // Copy data to kernel space buffer //
  bytesUnWritten = copy_from_user((void *)(device->circle_buff_entry.buffptr + device->circle_buff_entry.size),
                                     buf, count);
  if (bytesUnWritten == 0){
    PDEBUG("All bytes are written to kernel space");
  }
  bytesWrittenToKernelSpace = count - bytesUnWritten;
  device->circle_buff_entry.size += bytesWrittenToKernelSpace;
  
  // Check for \n //
  if (memchr(device->circle_buff_entry.buffptr, '\n', device->circle_buff_entry.size)){
    write_entry = aesd_circular_buffer_add_entry(&device->circle_buff, &device->circle_buff_entry);
    if (write_entry){
      kfree(write_entry);
    }
    device->circle_buff_entry.buffptr = NULL;
    device->circle_buff_entry.size = 0;
  }

  // No return check for mutex unlock //
  device->buf_size += bytesWrittenToKernelSpace;
  mutex_unlock(&device->lock);
  return bytesWrittenToKernelSpace;
}
struct file_operations aesd_fops = {
  .owner = THIS_MODULE,
  .read = aesd_read,
  .write = aesd_write,
  .open = aesd_open,
  .release = aesd_release,
  .llseek = aesd_llseek,
  .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev){
  int err, devno = MKDEV(aesd_major, aesd_minor);

  cdev_init(&dev->cdev, &aesd_fops);
  dev->cdev.owner = THIS_MODULE;
  dev->cdev.ops = &aesd_fops;
  dev->buf_size = 0;
  err = cdev_add(&dev->cdev, devno, 1);
  if (err){
    printk(KERN_ERR "Error %d adding aesd cdev", err);
  }
  return err;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
  struct aesd_dev *dev = filp->private_data;

  if (whence == SEEK_SET)
    filp->f_pos = offset;
  else if (whence == SEEK_CUR)
    filp->f_pos = filp->f_pos + offset;
  else if (whence == SEEK_END)
    filp->f_pos = dev->buf_size - offset;
  else
    return -EINVAL;

  if (filp->f_pos < 0)
    return -EINVAL;
  
  if (filp->f_pos > dev->buf_size)
    return -EINVAL;
  return filp->f_pos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  struct aesd_dev *dev = filp->private_data;
  loff_t locOffset = 0;
  struct aesd_seekto seekToCmd;
  struct aesd_buffer_entry *entry;
  uint32_t index = 0;
  long retval = 0;
  
  if (cmd == AESDCHAR_IOCSEEKTO)
    {
      retval = copy_from_user(&seekToCmd, (struct aesd_seekto __user *)arg, sizeof(struct aesd_seekto));

      if ((seekToCmd.write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) || (seekToCmd.write_cmd < 0) ){
        retval = -EINVAL;
        return retval;
      }
      
      while( index < seekToCmd.write_cmd) {
        entry = &dev->circle_buff.entry[index];
        if ((entry->size > 0) && (entry->buffptr != NULL))
          locOffset += entry->size;
        ++index;
      }
      entry = &dev->circle_buff.entry[seekToCmd.write_cmd];
      if ((entry->size > 0) && (entry->buffptr != NULL)){
        if (seekToCmd.write_cmd_offset > entry->size) {   // Return EINVAL if the offset is greater than size //
          retval = -EINVAL;
          return retval;
        }
        locOffset += seekToCmd.write_cmd_offset;
      } 
      filp->f_pos = locOffset;                            // Update Offset //
    }
  return retval;
}

int aesd_init_module(void){
  dev_t dev = 0;
  int result;
  result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
  aesd_major = MAJOR(dev);
  if (result < 0){
    printk(KERN_WARNING "Can't get major %d\n", aesd_major);
    return result;
  }
  memset(&aesd_device, 0, sizeof(struct aesd_dev));

  // Init Mutex //
  mutex_init(&aesd_device.lock);
  // Init Circular buffer //
  aesd_circular_buffer_init(&aesd_device.circle_buff);

  result = aesd_setup_cdev(&aesd_device);

  if (result){
    unregister_chrdev_region(dev, 1);
  }
  return result;
}

void aesd_cleanup_module(void){
  uint8_t index = 0;
  struct aesd_buffer_entry *entry = NULL;
  dev_t devno = MKDEV(aesd_major, aesd_minor);

  cdev_del(&aesd_device.cdev);

  // Free buffptr //
  kfree(aesd_device.circle_buff_entry.buffptr);

  AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circle_buff, index){
    if (entry->buffptr != NULL){
      kfree(entry->buffptr);
    }
  }
  unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
