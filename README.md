# EncryptDecryptShell
滴水三期项目-加密解密壳

### 由于在壳子项目中引用了加壳项目的头文件
需要右键壳子项目-》属性 -》C/C++ -》常规 -》附加包含目录 -》添加 $(SolutionDir)\\加壳项目;

需要右键壳子项目-》属性 -》链接器 -》常规 -》附加库目录 -》添加 $(SolutionDir)\\加壳项目;

### 图片如下

![image](images/shell.png)

![image](images/src.png)