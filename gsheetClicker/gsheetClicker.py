import sys

import gspread
import time


def main(target):
    sheet_name = "експеримент з таблицею"
    wks_name = "Лист1"
    start_time = time.localtime()
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
    wks = sh.worksheet(wks_name)
    while True:
        if start_time.tm_hour == 5 and start_time.tm_min == 55:
            center_row = 0
            center_col = 0
            cell_found = False
            print(f'GSheetClicker is Started! at {start_time.tm_hour}:{start_time.tm_min}')
            for col in range(10):
                if col == 0:
                    continue
                for row in range(10):
                    if row == 0:
                        continue
                    if wks.cell(row, col).value is None:
                        continue
                    if wks.cell(row, col).value == target:
                        cell_found = True
                        center_col = col
                        center_row = row
                        break
                if cell_found:
                    break
            if center_col == 0 or center_row == 0:
                print("Your cell haven't been found! Check your file Structure!\n")
                exit(0)
            center_row = center_row + 2
            for i in range(29):
                if i < center_row:
                    continue
                wks.update_cell(i, center_col, "✅")
                print(f'Check was made into cell({center_row},{center_col}) at {start_time.tm_hour}:{start_time.tm_min}')
                print("\n Sleeping for 60 minutes")
                time.sleep(3600)
        else:
            continue


if __name__ == '__main__':
    try:
        target = sys.argv[1]
    except:
        target = "7 ЦЗІ та КБ в ІТС"
    main(target)
