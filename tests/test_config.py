from src.utils.config import Config

def test_max_sub_iterations_exists():
    assert Config.MAX_SUB_ITERATIONS == 5

def test_max_depth_removed():
    assert not hasattr(Config, "MAX_DEPTH")
