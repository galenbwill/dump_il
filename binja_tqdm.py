from binaryninja import BackgroundTask, log_warn, log_alert

# from glenn

# Show a progress indicator for consuming an iterator
def tqdm(iterator, alert=False):
    bt = BackgroundTask()
    try:
        l = len(iterator)

        for (i, item) in enumerate(iterator):
            bt.progress = f'{i} / {l}  ({round(i / l * 100, 1)}%)'
            yield item

    except Exception as e:
        msg = f'Exception during iteration: {e}'
        if alert:
            log_alert(msg)
        else:
            log_warn(msg)
    finally:
        bt.finish()