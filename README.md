# cryptopals

## 运行环境
* python 3
* Linux: python中文件寻址会根据工作路径，而非文件所在路径进行寻址，因此本人采用`sys.path[0]+"\*.txt"`的方式指定文件位置，此方式可能导致部分脚本无法在Windows等环境中运行
* pycryptodemo： `Crypto`来自`pycryptodemo`库，此库为最新的正在不断维护的密码库

## Tips
1. **使用vim系编辑器复制粘贴外部文件时，请在`insert`模式下粘贴外部数据。**

   本人发现在neovim命令模式下使用`ctrl+shift+v`方式粘贴时，结尾会多出1个字符。`

2. **产生ct_list时，对line请使用line.strip()。**vim系编辑器会在最后一行未加换行符时自动添加换行符，因此对于一行（行）读取的读取方式请在文件积极使用strip（）方法去除换行符。

   本人因使用neovim编辑外部文件时，vim自动在文章末尾加上`’/n'`而导致报错，因加上`strip（）`方法。

   ```python	
   Traceback (most recent call last):
     File "/home/rean/work/crypto/xdu/PA2-AES/PA2-AES/sample.py", line 12, in <module>
       ctext = [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]
     File "/home/rean/work/crypto/xdu/PA2-AES/PA2-AES/sample.py", line 12, in <listcomp>
       ctext = [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]
   ValueError: invalid literal for int() with base 16: '\n'
   ```

3. `byte`类型的数据串索引得到的为`int`类型数据
    ```python
    >>> str1 = b'ICE ICE BABY\x04\x04\x04\x04'
    >>> str1[0]
    73
    >>> str1[-1]
    4
    >>> type(str1[-1])
    <class 'int'>
    ```

   

