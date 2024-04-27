import torch
import config
from transformers import RobertaTokenizer, RobertaModel, logging

logging.set_verbosity_error()

codebert_model_path = config.codebert_model_path

class CodeBertEmbedding():
    def __init__(self, model_file = codebert_model_path) -> None:

        """
        ['len = strlen(str)', '!is_privileged(user)', 'clear(str)', 'user++']
        """
        self.tokenizer = RobertaTokenizer.from_pretrained(model_file)
        self.model = RobertaModel.from_pretrained(model_file)

        self.max_m = 500
        

    def tokens(self, codes):
        tokens = [self.tokenizer.cls_token]

        for code in codes:
            tokens += self.tokenizer.tokenize(code)
            tokens += [self.tokenizer.sep_token]

        tokens = tokens[:-1] + [self.tokenizer.eos_token]

        return tokens


    def embeddings(self, codes):

        code_embeddings = []
        for code in codes:
            code_embedding = self.embedding(code)
            
            # sometime it is zero
            if code_embedding.numel() == 0 or code_embedding.shape ==  torch.Size([]):
                continue
            
            # print(code_embedding, code, code_embedding.shape)
            
            code_embeddings.append(code_embedding)
            
        code_embeddings = torch.stack(code_embeddings)
        # print(f"code_emb: {code_embeddings.shape}")
        embeddings = torch.mean(code_embeddings.squeeze(), dim=0)
        return embeddings
    
    def embedding(self, code):
        tokens_ids = self.tokenizer.convert_tokens_to_ids(self.tokenizer.tokenize(code))

        if len(tokens_ids) < self.max_m:
            # print(code, tokens_ids)
            
            code_embedding = self.model(torch.tensor(tokens_ids)[None, :])[0]  # type: ignore

            # print(code_embedding.shape)
            code_embedding = torch.mean(code_embedding.squeeze(), dim=0)
            
        else:
            code_embedding = []

            for i in range(0, len(tokens_ids), 500):
                batch_token_ids = tokens_ids[i:i+500]
                batch_code_embedding = self.model(torch.tensor(batch_token_ids)[None, :])[0]
                code_embedding.append(batch_code_embedding.squeeze())

            code_embedding = torch.cat(code_embedding, dim=0)
            code_embedding = torch.mean(code_embedding, dim=0)
        return code_embedding
    
# cbe = CodeBertEmbedding()
