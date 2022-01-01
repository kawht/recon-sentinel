#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
#sys.path.insert(0, "/opt/system/")
import wiringpi2

line1 = sys.argv[1]
line1 = str(line1)
line1 = line1.rstrip()

line2 = sys.argv[2]
line2 = str(line2)
line2 = line2.rstrip()

LCD_ROW = 2 # 16 Char
LCD_COL = 16 # 2 Line
LCD_BUS = 4 # Interface 4 Bit mode

PORT_LCD_RS = 7 # GPIOY.BIT3(#83)
PORT_LCD_E = 0 # GPIOY.BIT8(#88)
PORT_LCD_D4 = 2 # GPIOX.BIT19(#116)
PORT_LCD_D5 = 3 # GPIOX.BIT18(#115)
PORT_LCD_D6 = 1 # GPIOY.BIT7(#87)
PORT_LCD_D7 = 4 # GPIOX.BIT4(#104)


wiringpi2.wiringPiSetup()
lcdHandle = wiringpi2.lcdInit(LCD_ROW, LCD_COL, LCD_BUS,
PORT_LCD_RS, PORT_LCD_E,
PORT_LCD_D4, PORT_LCD_D5,
PORT_LCD_D6, PORT_LCD_D7, 0, 0, 0, 0);


# Clear LCD
wiringpi2.lcdClear(lcdHandle)

# Write string on LCD
wiringpi2.lcdPosition(lcdHandle, 0, 0)
wiringpi2.lcdPuts(lcdHandle, line1)
wiringpi2.lcdPosition(lcdHandle, 0, 1)
wiringpi2.lcdPrintf(lcdHandle, line2)

