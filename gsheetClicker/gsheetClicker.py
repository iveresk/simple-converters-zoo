import sys
from random import random

import gspread
import time
from datetime import datetime
from pytz import timezone
from tzwhere import tzwhere


def main(target):
    # setupping a set of parameters
    sheet_name = "Оперативна обстановка"
    wks_name = "Аркуш1"
    # connecting to the Google Sheet
    try:
        sa = gspread.service_account(filename="service-account.json")
    except:
        print(f'''
        There is no Server Account Key on the server. 
        Please see Google Cloud manual: 
        https://www.youtube.com/watch?v=bu5wXjz2KvU
        ''')
        exit(0)
    sh = sa.open(sheet_name)
    # connceting to the list
    wks = sh.worksheet(wks_name)
    timeZoneObj = timezone("Europe/Kiev")
    # checking if we have a target column, and it is valid for filling in
    center_row = 0
    center_col = 0
    cell_found = False
    for col in range(10):
        # missing unsupported cells
        if col == 0:
            continue
        for row in range(10):
            if row == 0:
                continue
            # missing empty cells
            if wks.cell(row, col).value is None:
                continue
            if wks.cell(row, col).value == target:
                # we've found our target cell
                cell_found = True
                center_col = col
                center_row = row
                break
        if cell_found:
            break
    # double-checking if cell is actually found and wasn't just an empty pass through
    if center_col == 0 or center_row == 0:
        print("Your cell haven't been found! Check your file Structure!\n")
        exit(0)
    else:
        print(f'The start column is found at {center_row} and {center_col}\n')
    while True:
        # updating cell_info
        start_time = datetime.now(timeZoneObj)
        if 8 <= start_time.time().hour <= 23:
            center_row = start_time.time().hour - 3
        else:
            center_row = start_time.time().hour + 21
        # taking random to 'simulate human behaviour'
        rng = random.SystemRandom()
        xrng = rng.randint(0, 3)
        if start_time.time().minute >= 51 + xrng:
            # correcting our row position from target cell
            try:
                wks.update_cell(center_row, center_col, "✅")
                print(f'Check was made into cell({center_row},{center_col}) '
                      f'at {start_time.time().hour}:{start_time.time().minute}')
                print("\n Sleeping for 60 minutes")
                time.sleep(3600)
            except Exception as e:
                print(e)
                time.sleep(25)
                try:
                    wks.update_cell(center_row, center_col, "✅")
                    time.sleep(3600)
                except:
                    print("\n The second attempt failed")
                pass
            except:
                time.sleep(25)
                try:
                    wks.update_cell(center_row, center_col, "✅")
                    time.sleep(3600)
                except:
                    print("\n The second attempt failed")
                pass
            finally:
                time.sleep(25)
                try:
                    wks.update_cell(center_row, center_col, "✅")
                    time.sleep(3600)
                except:
                    print("\n The third attempt failed")
                pass
        else:
            time.sleep(60)


if __name__ == '__main__':
    try:
        target = sys.argv[1]
    except:
        target = "7 ЦЗІ та КБ в ІТС"
    main(target)
