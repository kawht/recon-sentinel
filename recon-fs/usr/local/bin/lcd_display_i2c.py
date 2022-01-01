#!/usr/bin/python
import I2C_LCD_driver
from time import *
import sys


line1 = sys.argv[1]
line1 = str(line1)
line1 = line1.rstrip()

line2 = sys.argv[2]
line2 = str(line2)
line2 = line2.rstrip()


mylcd = I2C_LCD_driver.lcd()
mylcd.lcd_clear()
mylcd.lcd_display_string(line1, 1)
mylcd.lcd_display_string(line2, 2)
