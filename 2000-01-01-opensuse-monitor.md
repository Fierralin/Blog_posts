---
layout: post
title: "opensuse顯示器分辨率設置"
date: 2016-12-19 11:27:07
tags: UNIX
description: 設置顯示器沒有出現提供選擇的分辨率
duoshuo: true
---

一塊`1280x1024`的方屏在kde下面居然只能顯示成`1024x768`, 所以想要調整一下。

進去設置，選中顯示器一看，居然最高就只有`1024x768`的選項。

Bing搜索`KDE monitor add undetected resolutions`，結果搜到*fedora*大法，進而從回覆中搜到了*Arch*大法的終極方案。
研究一番搞定。描述如下：

首先執行`xrandr`命令（不用參數），輸出如下：

```
Screen 0: minimum 320 x 200, current 2720 x 1024, maximum 8192 x 8192
HDMI-1 disconnected (normal left inverted right x axis y axis)
HDMI-2 connected primary 1440x900+0+0 (normal left inverted right x axis y axis) 408mm x 255mm
   1440x900      59.89 +  74.98* 
   1280x1024     75.02    60.02  
   1152x864      75.00  
   1024x768      75.03    70.07    60.00  
   832x624       74.55  
   800x600       72.19    75.00    60.32    56.25  
   640x480       75.00    72.81    66.67    59.94  
   720x400       70.08  
DP-1 connected 1280x1024+1440+0 (normal left inverted right x axis y axis) 0mm x 0mm`
   1280x1024_60.00  59.89*+ （我已經完成設置了，本來沒有這一行，且*號在1024x768項後面）
   1024x768      60.00
   800x600       60.32    56.25  
   848x480       60.00  
   640x480       59.94  
HDMI-3 disconnected (normal left inverted right x axis y axis)
```

這裏列出了所有顯示器接口及所連顯示器的可選分辨率，其中DP-1, HDMI-2連有顯示器。我要改的是DP-1所連方屏的分辨率。

在已知DP-1顯示器分辨率能有`1280x1024`的情況下，改分辨率就好辦多了。
執行`cvt 1280 1024`輸出

> 1280x1024 59.89 Hz (CVT 1.31M4) hsync: 63.67 kHz; pclk: 109.00 MHz                                                                       
Modeline "1280x1024_60.00"  109.00  1280 1368 1496 1712  1024 1027 1034 1063 -hsync +vsync

這裏得到`1280x1024`分辨率對應的參數，後續添加分辨率就用這個參數。再依次執行
 `xrandr --newmode "1280x1024_60.00"  109.00  1280 1368 1496 1712  1024 1027 1034 1063 -hsync +vsync`
 `xrandr --addmode DP-1 1280x1024_60.00`
 `xrandr --output DP-1 --mode 1280x1024_60.00`
這樣，DP-1的分辨率就瞬間變成`1280x1024`了。
然而，進去KDE的設置裏面，仍然沒有該分辨率的選項。

要想做到可以在KDE系統裏面找到該設置項，做法如下
進入`/etc/X11/xorg.conf.d/`目錄，可以看到

> 50-monitor.conf
50-screen.conf

兩個文件。雖然Arch大法裏面說的配置文件是`10-monitor.conf`，但是畢竟發行版不一樣，時代也在變遷，配置文件也會變的，直接在這裏改就行了。
而且，這兩個文件裏面還貼心地給出了實例呢！
言歸正傳，在`50-monitor.conf`裏面添加如下內容：
```
Section "Monitor"
  Identifier "DP-1"
  Modeline "1280x1024_60.00"  109.00  1280 1368 1496 1712  1024 1027 1034 1063 -hsync +vsync
  Option "PreferredMode" "1280x1024_60.00"
EndSection
```

在`50-screen.conf`添加：
```
Section "Screen"
  Identifier "ScreenDock"
  Monitor "DP-1"
EndSection
```

重新登錄一下，就能在KDE的設置裏面看到DP-1所連接的顯示器有了`1280x1024`分辨率了，選中即可。
