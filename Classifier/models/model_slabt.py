import torch
import torch.nn as nn
import numpy as np
from transformers.models.bert.modeling_bert import BertModel


class AutoModelForSlabt(nn.Module):
    def __init__(self, pretrained_path, config, args=None, cls_num=7):
        super(AutoModelForSlabt, self).__init__()

        self.bert_config = config
        self.bert = BertModel.from_pretrained(pretrained_path)
        print(self.bert.config)
        self.fc1 = nn.Linear(self.bert_config.hidden_size, cls_num)     #注意外面也改了fc1


        # for tables
        # for different levels
        self.register_buffer('pre_features', torch.zeros(args.n_feature, args.feature_dim))
        self.register_buffer('pre_weight1', torch.ones(args.n_feature, 1))
        if args.n_levels > 1:
            self.register_buffer('pre_features_2', torch.zeros(args.n_feature, args.feature_dim))
            self.register_buffer('pre_weight1_2', torch.ones(args.n_feature, 1))
        if args.n_levels > 2:
            self.register_buffer('pre_features_3', torch.zeros(args.n_feature, args.feature_dim))
            self.register_buffer('pre_weight1_3', torch.ones(args.n_feature, 1))
        if args.n_levels > 3:
            self.register_buffer('pre_features_4', torch.zeros(args.n_feature, args.feature_dim))
            self.register_buffer('pre_weight1_4', torch.ones(args.n_feature, 1))
        if args.n_levels > 4:
            print('WARNING: THE NUMBER OF LEVELS CAN NOT BE BIGGER THAN 4')

    def forward(
            self,
            input_ids,
            attention_mask=None,
            token_type_ids=None
    ):
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            output_hidden_states=True
        )
        last_hidden_state = outputs[0]
        pooler_output = outputs[1] # (batch_size, hidden_size)

        # ii = input_ids.detach().cpu()
        # aa = attention_mask.detach().cpu()
        # tt = token_type_ids.detach().cpu()
        # file_path = 'bertencoder2.txt'
        # with open(file_path, "a") as f:
        #     for iii in ii.numpy():
        #         np.savetxt(f, iii, delimiter=",", fmt="%d", newline=",", header="", footer="\n", comments="")

        #     for aaa in aa.numpy():
        #         np.savetxt(f, aaa, delimiter=",", fmt="%d", newline=",", header="", footer="\n", comments="")
        #     for ttt in tt.numpy():
        #         np.savetxt(f, ttt, delimiter=",", fmt="%d", newline=",", header="", footer="\n", comments="")
    
        x = self.fc1(pooler_output) # [bsz, classes_num]  #最后加一个fc作为分类器x是分类分布概率
	
        #x = nn.functional.softmax(x, dim=1)

        hidden_states = outputs[2]

        return x, pooler_output, hidden_states
