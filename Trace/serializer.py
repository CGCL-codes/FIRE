import json
from typing import Iterable
import numpy as np
import redis
import config

redis_host = config.redis_host
redis_port = config.redis_port


class Serializer:
    def __init__(self, host=redis_host, port=redis_port) -> None:
        self.host = host
        self.port = port

        self.r_patch_line_dict = redis.Redis(host=host, port=port, db=0)
        self.r_patch_hash_dict = redis.Redis(host=host, port=port, db=1)
        self.r_diff_embedding_dict = redis.Redis(host=host, port=port, db=2)
        self.r_error_func_list = redis.Redis(host=host, port=port, db=3)
        self.r_fuzzy_hash = redis.Redis(host=host, port=port, db=4)

    def set(self, handler, k, v):
        v = json.dumps(v)
        handler.set(k, v)

    def get(self, handler, k):
        v = handler.get(k)
        if v is not None:
            v = json.loads(v)  # type: ignore
        return v

    def set_patch_line(self, k, v: Iterable):
        self.set(self.r_patch_line_dict, k, v)

    def get_patch_line(self, k):
        return self.get(self.r_patch_line_dict, k)

    def set_line_hash_dict(self, k, v: Iterable):
        self.set(self.r_patch_hash_dict, k, v)

    def get_line_hash_dict(self, k):
        return self.get(self.r_patch_hash_dict, k)

    def set_diff_embedding(self, k, v: Iterable[np.ndarray]):
        lv = tuple(map(lambda n: n.tolist(), v))
        self.set(self.r_diff_embedding_dict, k, lv)

    def get_diff_embedding(self, k):
        v = self.get(self.r_diff_embedding_dict, k)
        if v is None:
            return None
        v = tuple(np.array(arr) for arr in v)
        return v

    def set_error_func(self, k):
        self.r_error_func_list.set(k, 1)

    def is_error_func(self, k):
        v = self.r_error_func_list.get(k)
        return v is not None

    def set_fuzzy_hash(self, k, v):
        self.set(self.r_fuzzy_hash, k, v)

    def get_fuzzy_hash(self, k):
        return self.get(self.r_fuzzy_hash, k)


if __name__ == "__main__":
    s = Serializer()
    s.set_diff_embedding("1", (np.array([1.0, 2.0]), np.array([3.0, 4.0])))
    print(s.get_diff_embedding("1"))

    s.set_patch_line("1", [("12", "34"), ("56", "78")])
    print(s.get_patch_line("1"))

    s.set_error_func("1")
    print(s.is_error_func("1"))
