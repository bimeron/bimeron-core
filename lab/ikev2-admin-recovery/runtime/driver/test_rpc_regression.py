"""Run preserved accepted RPC/timing behavior with the new child-env seam.

Two historical byte-equality/reproducer cases refer to a superseded source layout;
the behavioral RPC and timing cases are preserved. All children are inert.
"""
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import stock_controller

sys.dont_write_bytecode=True
ROOT=pathlib.Path(__file__).resolve().parents[2]
SOURCE=ROOT.parent/'source/build/e775-stock-ui/rpc-evidence-delta-v2'
OUT=pathlib.Path(tempfile.mkdtemp(prefix='rpc-tests-',dir=ROOT))


def load(name):
    raw=(SOURCE/(name+'.py')).read_text(encoding='utf-8-sig')
    module=types.ModuleType(name);module.__file__=str(SOURCE/(name+'.py'))
    if name=='test_rpc_delta':
        raw=raw.replace("D=pathlib.Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,str(D/'candidate'))",
                        'D=pathlib.Path('+repr(str(OUT))+');sys.dont_write_bytecode=True')
    sys.modules[name]=module
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


if __name__=='__main__':
    first=load('test_rpc_delta');second=load('test_timing')
    names=unittest.defaultTestLoader.getTestCaseNames(first.Tests)
    excluded={'test_original_nonzero_reproduction_below_popen','test_exact_reused_helpers_and_unchanged_logic'}
    suite=unittest.TestSuite([first.Tests(n) for n in names if n not in excluded])
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(second.Timing))
    with patch.object(stock_controller,'_stock_child_environment',return_value={'PSModulePath':'INERT-VALIDATED'}):
        result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
