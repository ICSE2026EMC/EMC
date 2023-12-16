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
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score


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
    true_sum = []
    pred_sum = []
    with torch.no_grad():
        end = time.time()
        for i, (input_ids, attention_masks, segment_ids, target) in enumerate(val_loader):

            input_ids = input_ids.cuda(args.gpu, non_blocking=True)
            attention_masks = attention_masks.cuda(args.gpu, non_blocking=True)
            segment_ids = segment_ids.cuda(args.gpu, non_blocking=True)
            target = target.cuda(args.gpu, non_blocking=True)

            output, cfeatures, hidden_states = model(input_ids, attention_masks, segment_ids)
            # if epoch == 1:
            #     bertencoder = cfeatures.detach().cpu()
            #     labels = target.detach().cpu()
            #     with open('bertencoder111.txt','a+') as f:
            #         for value, label in zip(bertencoder.numpy(), labels.numpy()):
            #             #f.write(str(value) + "    " + str(label) + "\n")
            #             np.savetxt(f, value, delimiter=",", newline=",", header="", footer="\n", comments="")
            #             f.write(str(label) + "\n")
            # if epoch == 2:
            #     bertencoder = cfeatures.detach().cpu()
            #     labels = target.detach().cpu()
            #     with open('bertencoder112.txt','a+') as f:
            #         for value, label in zip(bertencoder.numpy(), labels.numpy()):
            #             #f.write(str(value) + "    " + str(label) + "\n")
            #             np.savetxt(f, value, delimiter=",", newline=",", header="", footer="\n", comments="")
            #             f.write(str(label) + "\n")
            # if epoch == 3:
            #     bertencoder = cfeatures.detach().cpu()
            #     labels = target.detach().cpu()
            #     with open('bertencoder113.txt','a+') as f:
            #         for value, label in zip(bertencoder.numpy(), labels.numpy()):
            #             #f.write(str(value) + "    " + str(label) + "\n")
            #             np.savetxt(f, value, delimiter=",", newline=",", header="", footer="\n", comments="")
            #             f.write(str(label) + "\n")
            # if epoch == 6:
            #     bertencoder = cfeatures.detach().cpu()
            #     labels = target.detach().cpu()
            #     with open('bertencoder116.txt','a+') as f:
            #         for value, label in zip(bertencoder.numpy(), labels.numpy()):
            #             #f.write(str(value) + "    " + str(label) + "\n")
            #             np.savetxt(f, value, delimiter=",", newline=",", header="", footer="\n", comments="")
            #             f.write(str(label) + "\n")

            loss = criterion(output, target)

            acc1, acc5 = accuracy(output, target, topk=(1, 1), args=args, datasetname=datasetname)
            
            #print(len(true_sum),len(pred_sum))
            _, pred = output.topk(1, 1, True, True)
            y_pred = pred.flatten().tolist()
            pred = pred.t()
            y_true = target.tolist()
            pred_sum.extend(y_pred)
            true_sum.extend(y_true)
            #print(len(true_sum),len(pred_sum))


            losses.update(loss.item(), input_ids.size(0))
            top1.update(acc1[0], input_ids.size(0))

            batch_time.update(time.time() - end)
            end = time.time()

            # if i % args.print_freq == 0:
            #     method_name = args.log_path.split('/')[-2]
            #     progress.display(i, method_name)     #每个batch的val信息
            #     progress.write_log(i, args.log_path)
        #     if epoch == 7:
		# # 将标签向量转换为 NumPy 数组
        #         labels = target.cpu().numpy()
        #         feature_np = input_ids.cpu().numpy()
		# # 找到每个类别的向量的索引
        #         #indices = [np.where(labels == i)[0] for i in range(7)]
		# # 将每个类别的张量存储到不同的文件中
        #         for i in range(7):
		# # 找到属于当前类别的向量的索引
        #                 indices = np.where(labels == i)[0]
        #                 if len(indices) > 0:
        #                         class_tensors = feature_np[indices, :]

        #                         with open(f"/home/user/class/0/classv_{i}.npy", "ab") as f:
        #                                np.save(f, class_tensors)
        #                                numwrite = numwrite + 1




        conf_matrix = confusion_matrix(true_sum, pred_sum)
        # 计算精确率、召回率和F1分数
        precision, recall, f1, _ = precision_recall_fscore_support(true_sum, pred_sum, average='macro', zero_division=1)
        # 计算准确率
        acc = accuracy_score(true_sum, pred_sum)
        # 输出结果
        print(f'Precision: {precision:.3f}')
        print(f'Recall: {recall:.3f}')
        print(f'F1 Score: {f1:.3f}')
        print(f'Accuracy: {acc:.3f}')
        
        print(' * Acc_@1 {top1.avg:.3f}'.format(top1=top1))     #一个迭代的acc
        outputfile = args.output
        with open(outputfile, 'a+') as f:
            f.write(' * Acc@1 {top1.avg:.3f}'.format(top1=top1))
            f.write('   ' + str(acc))
            f.write('   ' +str(precision))
            f.write('   ' + str(recall))
            f.write('   ' + str(f1))
            f.write(' * loss {losses.avg}'.format(losses=losses))
            f.write(' * loss ' + str(losses.avg))
            f.write('\n')
        
        # if test:
        #     tensor_writer.add_scalar('loss/test', loss.item(), epoch)
        #     tensor_writer.add_scalar('ACC@1/test', top1.avg, epoch)
        # else:
        #     tensor_writer.add_scalar('loss/val', loss.item(), epoch)
        #     tensor_writer.add_scalar('ACC@1/val', top1.avg, epoch)

    return top1.avg
