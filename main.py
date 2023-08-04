import random
import time
import threading
from queue import Queue
import curses
import boto3
import botocore
import sys
from datetime import datetime
import logging
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

# set up colors
colorama_init()

# Create a logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create handlers
c_handler = logging.StreamHandler()
f_handler = logging.FileHandler('s3_chaos.log')
e_handler = logging.FileHandler('error.txt')  # handler for error file

# Set level for error handler
e_handler.setLevel(logging.ERROR)

# Create formatters and add it to handlers
format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
c_handler.setFormatter(format)
f_handler.setFormatter(format)
e_handler.setFormatter(format)  # formatter for error handler

# Add handlers to the logger
# logger.addHandler(c_handler)
logger.addHandler(f_handler)
logger.addHandler(e_handler)  # add error handler to the logger

# Constants
WORDLIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"
TARGET = "CPE1704TKS"
DELAY = 0.075

class PrinterThread(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def run(self):
        while True:
            msg = self.queue.get()
            if msg == 'Done':
                break
            print(f"{Fore.GREEN}{msg}", end='\r')
            time.sleep(DELAY)

def print_slowly(string, color=Fore.GREEN):
    """Prints a string slowly to stdout, one character at a time with a delay."""
    for ch in string:
        print(f"{color}{ch}", end='', flush=True)
        time.sleep(DELAY)

def create_target_word(cur, printer_queue):
    """Generates a random target word"""
    random.seed(time.time())
    threads = []
    for i in range(len(cur)):
        def make_thread(i):
            def thread():
                while cur[i] != TARGET[i]:
                    time.sleep(DELAY)
                    cur[i] = random.choice(WORDLIST)
                    printer_queue.put(''.join(cur))
            return thread
        threads.append(threading.Thread(target=make_thread(i)))
        threads[-1].start()

    for thread in threads:
      thread.join()
    printer_queue.put('Done')

def display_intro_text():
    """Displays the introduction text with pauses."""
    print_slowly("GREETINGS PROFESSOR FALKEN\n\n")
    print_slowly("\nSHALL WE PLAY A GAME?\n")
    input()
    print_slowly("\nA STRANGE GAME.\n")
    print_slowly("THE ONLY WINNING MOVE\n")
    print_slowly("IS NOT TO PLAY.\n")
    time.sleep(2)
    print_slowly("\nHOW ABOUT A NICE GAME OF SECURITY CHAOS ENGINEERING?\n")
    time.sleep(2)
    print_slowly("\nHERE ARE A FEW EXPERIMENTS TO CHOOSE FROM:\n")
    time.sleep(2)

def print_menu(stdscr, options, selected_row):
    """Displays the menu of options for the user to select."""
    stdscr.clear()
    for idx, row in enumerate(options):
        x = 1
        y = idx
        if idx == selected_row:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, row)
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.addstr(y, x, row)
    stdscr.refresh()

def menu(stdscr, options):
    """Handles user interaction with the menu."""
    cur_row = 0
    print_menu(stdscr, options, cur_row)
    while True:
        key = stdscr.getch()
        if key == curses.KEY_UP and cur_row > 0:
            cur_row -= 1
        elif key == curses.KEY_DOWN and cur_row < len(options)-1:
            cur_row += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            return options[cur_row]
        print_menu(stdscr, options, cur_row)

# All experiemnt functions go here
def s3_bucket_versioning_chaos():
    print_slowly("\nPHASE 1 INITIALIZING - CHAOS\n")
    # Initialize the S3 client
    try:
      s3 = boto3.client('s3')

      # List all S3 buckets
      response = s3.list_buckets()
      all_buckets = [bucket['Name'] for bucket in response['Buckets']]
    except botocore.exceptions.NoCredentialsError:
        logger.error("Credentials not found.")
        print_slowly("\nACCESS DENIED!\n")
        sys.exit(1)

    if len(all_buckets) < 2:
        logger.warning("Not enough buckets to perform this test.")
        return

    # Randomly select two buckets and make sure we can access them
    valid_buckets = False
    while not valid_buckets:
      selected_buckets = random.sample(all_buckets, 2)
      for bucket in selected_buckets:
        try:
          # print(f"trying buckets {bucket}")
          versioning_status = s3.get_bucket_versioning(Bucket=bucket)
        except boto3.exceptions.botocore.exceptions.ClientError as e:
          valid_buckets = False
        else:
          valid_buckets = True


    for bucket in selected_buckets:
        try:
            # Get bucket versioning status
            versioning_status = s3.get_bucket_versioning(Bucket=bucket)

            # Check if versioning is enabled
            if versioning_status.get('Status') == 'Enabled':
                logger.info(f"Versioning enabled on {bucket}. Disabling now...")
                print(f"{Fore.RED}✅ - Versioning enabled on {bucket}. Disabling now..")

                # Disable versioning
                s3.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={'Status': 'Suspended'}
                )
                global disable_time
                disable_time = datetime.now()
                logger.info(f"Versioning disabled at: {disable_time}")
                print(f"{Fore.RED}✅ - Versioning disabled at: {disable_time}")
            else:
                logger.info(f"Versioning is already disabled on {bucket}")
                print(f"{Fore.RED}✅ - Versioning is already disabled on {bucket}")

        except boto3.exceptions.botocore.exceptions.ClientError as e:
            # Check if the error is 'AccessDenied'
            if e.response['Error']['Code'] == 'AccessDenied':
                # Log the error message and bucket name
                logger.error(f"Access Denied for bucket: {bucket}. Error: {str(e)}")
    print_slowly("\nPHASE 1 COMPLETE\n")

def s3_bucket_versioning_activation_test():
    print_slowly("\nPHASE 2 INITIALIZING - TESTING AND REMEDIATION\n")
    try:
      # Initialize the S3 client
      s3 = boto3.client('s3')

      # List all S3 buckets
      response = s3.list_buckets()
      all_buckets = [bucket['Name'] for bucket in response['Buckets']]
    except botocore.exceptions.NoCredentialsError:
        logger.error("Credentials not found.")
        print_slowly("\nACCESS DENIED!\n")
        sys.exit(1)

    for bucket in all_buckets:
        try:
            # Get bucket versioning status
            versioning_status = s3.get_bucket_versioning(Bucket=bucket)

            # Check if versioning is enabled
            if versioning_status.get('Status') != 'Enabled':
                logger.info(f"Versioning not enabled on {bucket}. Enabling now...")
                print(f"{Fore.BLUE}✅ - Versioning not enabled on {bucket}. Enabling now...")
                global discovered_time
                discovered_time = datetime.now()

                # Enable versioning
                s3.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                global enable_time
                enable_time = datetime.now()
                logger.info(f"Versioning enabled at: {enable_time}")
                print(f"{Fore.BLUE}✅ - Versioning enabled at: {enable_time}")

                remediation_time = (enable_time - discovered_time).total_seconds()
                logger.info(f"Time to remediate was: {remediation_time} seconds.")
                print(f"{Fore.BLUE}✅ - Time to remediate was: {remediation_time} seconds.")
            else:
                logger.info(f"Versioning is already enabled on {                bucket}\n")

        except boto3.exceptions.botocore.exceptions.ClientError as e:
            # Check if the error is 'AccessDenied'
            if e.response['Error']['Code'] == 'AccessDenied':
                # Log the error message and bucket name
                logger.error(f"Access Denied for bucket: {bucket}. Error: {str(e)}")

    print_slowly("\nPHASE 2 COMPLETE\n")
    # Message for user about the value of enabling versioning on their buckets
    print(
        f"\n{Style.RESET_ALL} "
        f"\nS3 Versioning Enabled on all buckets in the account. Successfully recovered back to steady state.\n"
        f"\n{Style.BRIGHT}Recovery from Accidental Deletion or Overwrites{Style.NORMAL}: With versioning enabled, all versions of an object "
        f"(including all writes and deletes) are stored. In case an attacker or a malicious script deletes or "
        f"overwrites objects, you can restore the data to a previous state.\n"
        f"\n{Style.BRIGHT}Protection from Ransomware{Style.NORMAL}: Ransomware attacks often involve the encryption of data and demand a "
        f"ransom for decryption. With versioning enabled, an older, unencrypted version of the data can be restored.\n"
        f"\n{Style.BRIGHT}Audit Trail{Style.NORMAL}: Versioning also keeps an audit trail of all changes made to an object. This can be "
        f"beneficial to investigate how and when your data was changed after a security incident.\n"
        f"\n{Style.BRIGHT}Easy Rollback{Style.NORMAL}: If the compromise leads to undesirable changes, having versioning on allows you to "
        f"quickly rollback to a previous version of your data.\n"
        f"\n{Style.BRIGHT}Regulatory Compliance{Style.NORMAL}: For many regulatory standards, preserving all versions of data and maintaining "
        f"an access history is a requirement. Versioning allows compliance with such standards."
        "\n "
    )

def main():
    """Main execution function"""
    cur = list(' ' * len(TARGET))
    printer_queue = Queue()
    printer_thread = PrinterThread(printer_queue)
    printer_thread.start()

    create_target_word(cur, printer_queue)

    printer_thread.join()

    print(''.join(cur))
    print()
    time.sleep(2)

    display_intro_text()

    options = ["S3 Bucket Versioning Activation Test",
               "AMI Public Accessibility Reversion Test",
               "Server Access Log Continuity Test"]

    curses.initscr()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
    selected_option = curses.wrapper(menu, options)
    print_slowly("\nYou selected: " + selected_option + "\n")

    # Execute the selected option
    if selected_option == "S3 Bucket Versioning Activation Test":
        s3_bucket_versioning_chaos()
        time.sleep(60)
        s3_bucket_versioning_activation_test()

if __name__ == "__main__":
  main()
