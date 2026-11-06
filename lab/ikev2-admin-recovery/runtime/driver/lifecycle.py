"""Latch reader errors without skipping owned finite-task cleanup."""
def settle_readers(futures, failure=None):
    for future in futures:
        try: future.result()
        except Exception as exc: failure = failure or str(exc)
    return failure


def wait_producer_ready(query, timeout=60, clock=None, pause=None):
    import time
    clock=clock or time.monotonic;pause=pause or time.sleep
    deadline=clock()+timeout
    while clock()<deadline:
        value=query()
        if value.get('failure'):raise RuntimeError('Producer readiness failed: '+str(value['failure']))
        if value.get('ready') is True and value.get('healthy') is True:return value
        pause(.2)
    raise TimeoutError('Producer readiness deadline; no readers launched')
