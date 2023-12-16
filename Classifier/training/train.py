import os
import random
import shutil
import time
import numpy as np
import torch
import torch.multiprocessing as mp
import torch.nn as nn
import torch.nn.parallel
import torch.optim
import torch.utils.data
import torch.utils.data.distributed
from torch.autograd import Variable
from utilis.matrix import accuracy
from utilis.meters import AverageMeter, ProgressMeter

from training.reweighting import weight_learner
from transformers import get_linear_schedule_with_warmup
from info_regularizer import train_mi_upper_estimator


def train(train_loader, model, criterion, optimizer, epoch, args, tensor_writer=None, mi_upper_estimator=None, dow=None, flag=""):
    ''' TODO write a dict to save previous featrues  check vqvae,
        the size of each feature is 512, os we need a tensor of 1024 * 512
        replace the last one every time
        and a weight with size of 1024,
        replace the last one every time
        TODO init the tensors

        args:
            tensor_writer: SummaryWriter(log_dir)
    '''

    batch_time = AverageMeter('Time', ':6.3f')
    data_time = AverageMeter('Data', ':6.3f')
    losses = AverageMeter('Loss', ':.4e')
    top1 = AverageMeter('Acc@1', ':6.2f')
    ub_loss = AverageMeter('ub_loss', ':6.2f')

    progress = ProgressMeter(
        len(train_loader),
        [batch_time, data_time, losses, top1, ub_loss],
        prefix="Epoch: [{}]".format(epoch)) 
    ll = len(train_loader)
    training_steps = (len(train_loader) - 1 / args.epochs + 1) * args.epochs
    
    lr_scheduler = get_linear_schedule_with_warmup(
        optimizer=optimizer,
        num_warmup_steps = 0.1 * training_steps,
        num_training_steps=training_steps
        )

    numwrite = 0
    model.train()

    end = time.time()
    for i, (input_ids, attention_masks, segment_ids, target) in enumerate(train_loader):
        data_time.update(time.time() - end)

        upperbound_loss = 0.0

        input_ids = input_ids.cuda(args.gpu, non_blocking=True)
        attention_masks = attention_masks.cuda(args.gpu, non_blocking=True)
        segment_ids = segment_ids.cuda(args.gpu, non_blocking=True)
        target = target.cuda(args.gpu, non_blocking=True)
        torch.cuda.empty_cache()
        output, cfeatures, hidden_states = model(input_ids, attention_masks, segment_ids) #output 当前样本预测各个类别的概率, flatten_features是clstoken(CLS的token（hidden_states[0]）再过一下全连接层+Tanh激活函数得到的，作为该句子的特征向量), hidden_states（bert各层输出的所有的token） // 
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
        
        pre_features = model.pre_features
        pre_weight1 = model.pre_weight1

        if epoch >= args.epochp:
            weight1, pre_features, pre_weight1 = weight_learner(cfeatures, pre_features, pre_weight1, args, epoch, i)

        else:
            weight1 = Variable(torch.ones(cfeatures.size()[0], 1).cuda())

        model.pre_features.data.copy_(pre_features)
        model.pre_weight1.data.copy_(pre_weight1)

        if flag == 'FeatDe' or flag == 'depro':
            loss = criterion(output, target).view(1, -1).mm(weight1).view(1)
        else:
            #print("no depro")
            loss = criterion(output, target).view(1, -1).mm(torch.ones_like(weight1)).view(1)


        

        if mi_upper_estimator:
            upper_bound = train_mi_upper_estimator(mi_upper_estimator, dow, hidden_states, attention_masks)
            loss += upper_bound
            upperbound_loss += upper_bound.item()

        # if epoch == 7:
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

        #                         with open(f"/home/user/class/0/class_{i}.npy", "ab") as f:
        #                                np.save(f, class_tensors)
        #                                numwrite = numwrite + 1


        acc1, _ = accuracy(output, target, topk=(1, 1))
        losses.update(loss.item(), input_ids.size(0))
        top1.update(acc1[0], input_ids.size(0))
        ub_loss.update(upperbound_loss, input_ids.size(0))

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        lr_scheduler.step()

        batch_time.update(time.time() - end)
        end = time.time()

        # method_name = args.log_path.split('/')[-2]
        # if i % args.print_freq == 0:
        #     progress.display(i, method_name)
        #     progress.write_log(i, args.log_path)


    # tensor_writer.add_scalar('loss/train', losses.avg, epoch)
    # tensor_writer.add_scalar('ACC@1/train', top1.avg, epoch)
    print(numwrite)

