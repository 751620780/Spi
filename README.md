# <strong>Spi</strong>
Windows上一款基于Spi的windows socket2网络流量透明加密传输工具<br>
说明：<br>
1.使用vs2015打开FilterSocket.sln来进行编译，默认是x86的release方式，在release文件夹下有安装说明和注意事项<br>
2.每一个项目内均有readme文件，修改编译配置前打开后readme阅读后再进行修改也不迟<br>
3.该程序可以在xp以上版本运行(安装时请按照说明进行安装)<br>
下面对该目录下的文件夹进行说明：<br>
Install:是一个win32的控制台应用程序，它是用来安装/卸载spi程序的（其实质就是修改备份/恢复注册表的）<br>
Spi:是本项目的重中之重，其编译后生成Spi.dll这个dll是这个项目真正的程序。<br>
SpiManage：是Spi的配置管理工具，使用VS提供的MFC编写的windows 桌面应用程序(为了兼容xp才使用MFC的)，编译后将生成SpiManage.exe，这个工具目前只完成了一半（但是已经能够使用了，缺少的部分是查看日志和警报）<br>
Release:是整个解决方案编译生成二进制文件的目录，这里面提供了一个文件夹和一个Readme来解释为什么要这样安装的。<br>
