import sys
import traceback


def print_filtered_traceback(error, package_name="certapi"):
    """
    Prints the stack trace, stopping at the specified package,
    and excluding functions with names starting with '_'.

    :param error: The exception object.
    :param package_name: The package name to filter the trace.
    """
    tb = error.__traceback__
    filtered_tb = []

    while tb is not None:
        frame = tb.tb_frame
        function_name = frame.f_code.co_name
        if package_name in frame.f_globals.get("__name__", "") and not function_name.startswith("_"):
            filtered_tb.append(tb)
        tb = tb.tb_next

    if filtered_tb:
        print(f"Filtered traceback (up to package '{package_name}'):", file=sys.stderr)
        for tb in filtered_tb:
            frame = tb.tb_frame
            function_name = frame.f_code.co_name

            # Filter the actual stack trace to ensure no private functions appear
            if not function_name.startswith("_"):
                traceback.print_tb(tb, file=sys.stderr)
    else:
        print(f"No matching frames found in traceback for package '{package_name}'.", file=sys.stderr)
