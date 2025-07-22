import torch
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

def accuracy(output, target, topk=(1,), args=None, datasetname=None):
    """Computes the accuracy over the k top predictions for the specified values of k"""
    with torch.no_grad():
        maxk = max(topk)
        batch_size = target.size(0)

        _, pred = output.topk(maxk, 1, True, True)
        y_pred = pred.flatten().tolist()
        pred = pred.t()
        y_true = target.tolist()
        # print(y_true)
        # print(y_pred)
        if datasetname != None:
            if datasetname == 'HANS':
                tmp_zero = torch.zeros_like(pred).cuda(args.gpu, non_blocking=True)
                pred = torch.where(pred == 2, tmp_zero, pred).cuda(args.gpu, non_blocking=True)
        # print(pred)
        correct = pred.eq(target.view(1, -1).expand_as(pred))

        res = []
        for k in topk:
            correct_k = correct[:k].view(-1).float().sum(0, keepdim=True)
            res.append(correct_k.mul_(100.0 / batch_size))
        f1 = f1_score(y_true, y_pred, average='macro', zero_division = 0)
        recall = recall_score(y_true, y_pred, average='macro', zero_division = 0)
        precision = precision_score(y_true, y_pred, average='macro', zero_division = 0)
        accuracy1 = accuracy_score(y_true, y_pred)
        # print("F1", f1, recall, precision, accuracy1)
        # print(res)

        return res
