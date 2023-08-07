import time
import numpy as np
import torch
import torch.multiprocessing as mp
import torch.nn.parallel
import torch.optim
import torch.utils.data
import torch.utils.data.distributed
from utilis.matrix import accuracy
from utilis.meters import AverageMeter, ProgressMeter


def validate(val_loader, model, criterion, epoch=0, test=True, args=None, tensor_writer=None, datasetname=None):
    if test:
        batch_time = AverageMeter('Time', ':6.3f')
        losses = AverageMeter('Loss', ':.4e')
        top1 = AverageMeter('Acc@1', ':6.2f')
        progress = ProgressMeter(
            len(val_loader),
            [batch_time, losses, top1],
            prefix='Test: ')
    else:
        batch_time = AverageMeter('val Time', ':6.3f')
        losses = AverageMeter('val Loss', ':.4e')
        top1 = AverageMeter('Val Acc@1', ':6.2f')
        progress = ProgressMeter(
            len(val_loader),
            [batch_time, losses, top1],
            prefix='Val: ')

    model.eval()
    print('******************datasetname is {}******************'.format(datasetname))
    numwrite = 0
    with torch.no_grad():
        end = time.time()
        for i, (input_ids, attention_masks, segment_ids, target) in enumerate(val_loader):

            input_ids = input_ids.cuda(args.gpu, non_blocking=True)
            attention_masks = attention_masks.cuda(args.gpu, non_blocking=True)
            segment_ids = segment_ids.cuda(args.gpu, non_blocking=True)
            target = target.cuda(args.gpu, non_blocking=True)

            output, cfeatures, hidden_states = model(input_ids, attention_masks, segment_ids)
            loss = criterion(output, target)

            acc1, acc5 = accuracy(output, target, topk=(1, 1), args=args, datasetname=datasetname)
            losses.update(loss.item(), input_ids.size(0))
            top1.update(acc1[0], input_ids.size(0))

            batch_time.update(time.time() - end)
            end = time.time()

            if i % args.print_freq == 0:
                method_name = args.log_path.split('/')[-2]
                progress.display(i, method_name)
                progress.write_log(i, args.log_path)
            if epoch == 7:
		# 将标签向量转换为 NumPy 数组
                labels = target.cpu().numpy()
                feature_np = input_ids.cpu().numpy()
		# 找到每个类别的向量的索引
                #indices = [np.where(labels == i)[0] for i in range(7)]
		# 将每个类别的张量存储到不同的文件中
                for i in range(7):
		# 找到属于当前类别的向量的索引
                        indices = np.where(labels == i)[0]
                        if len(indices) > 0:
                                class_tensors = feature_np[indices, :]

                                with open(f"/home/user/class/3/classv_{i}.npy", "ab") as f:
                                       np.save(f, class_tensors)
                                       numwrite = numwrite + 1
        print(' * Acc@1 {top1.avg:.3f}'.format(top1=top1))
        with open('youhua3', 'a+') as f:
            f.write(' * Acc@1 {top1.avg:.3f}'.format(top1=top1))
            f.write('\n')
        
        if test:
            tensor_writer.add_scalar('loss/test', loss.item(), epoch)
            tensor_writer.add_scalar('ACC@1/test', top1.avg, epoch)
        else:
            tensor_writer.add_scalar('loss/val', loss.item(), epoch)
            tensor_writer.add_scalar('ACC@1/val', top1.avg, epoch)

    return top1.avg
