# Youpk4Pixel2XL
  `Youpk`是一种通过修改系统源码实现主动调用进行脱壳的工具，基于`android-7.1.2_r33`分支做的定制，仅支持`Pixel`机型，但该机型问题太多了，买了两个，一个时不时无限重启，一个充不进去电，正好身边有一部`Pixel 2 XL`用着还不错，并且`Pixel 2 XL`支持的最初始分支`android-8.0.0_r21`与`android-7.1.2_r33`分支挺近的，代码差别应该不是很大，就想把`Youpk`移植到`Pixel 2 XL`，正好也学习下`Youpk`的工作原理。 

  在此特感谢`Youpk`工具作者的开源精神，能搞出来肯定需要对越来越庞大的android源码有充分的了解。因此，我这个移植也会依照`Youpk`的格式开源。以及感谢在移植过程中，在网上搜索到的各种填坑文章，以及Google开源的Android源码，还有各种在线源码搜索服务，还有各种编译系统以及填坑的文章，以及现在越来越快的科学速度，以及各种涉及到的效率工具。 

  具体原理就不用讲了，参考Youpk即可，其实我也不太懂，我就只管移植完事即可,哈哈。  
  
  很少研究这方面，若是有遗漏地方大佬勿喷，欢迎提出来哈
# 与Youpk不同的地方
- `CompilerFilter::kVerifyAtRuntime`换成了`CompilerFilter::kVerify`  
- `mirror::ClassLoader*`换成了`ObjPtr<mirror::ClassLoader>`  
- `StringPrintf`换成了`android::base::StringPrintf`  
- `ReaderMutexLock mu(self, *class_linker->DexLock());`换成了`ReaderMutexLock mu(self, *Locks::dex_lock_);`  
- `ClassLinker`里好几个函数返回值变成了`ObjPtr<T>`格式  
- `PrettyMethod(method)`换成了`method->PrettyMethod()`  
- `NATIVE_METHOD`和`REGISTER_NATIVE_METHODS`位置发生了改变  
# 参考
- [Android6.0上frameworks增加代码编译错误](https://www.jianshu.com/p/634d71e31a9d)  
- [安卓脱壳速成](https://chinggg.github.io/post/fart/)  

# 最后
附上开源地址:[Humenger/Youpk4Pixel2XL](https://github.com/Humenger/Youpk4Pixel2XL)  


# 小工具
### 快捷导出更改过的文件
```python
# 需要放在out目录下执行
import os
import re
import sys
import zipfile
import shutil

os.system("rm -rf repo_status.txt")
os.system("rm -rf Youpk4Pixel2XL.zip")
os.system("rm -rf ./Youpk4Pixel2XL/")
os.system("repo status > repo_status.txt")
os.system("echo project >> repo_status.txt")
status=open("repo_status.txt","rb").read().decode()
for match in re.findall("project (.*?) branch Youpk4Pixel2XL([\s\S]*?)\n(?=project)",status):
    if match[1]:
        for sub in match[1].splitlines():
            if sub:
                relate_path=match[0].strip()+re.findall("[^\t\n]+", sub)[1]
                changed_file=os.path.abspath("../"+relate_path)
                target_file=os.path.abspath("./Youpk4Pixel2XL/"+relate_path)
                print(changed_file)
                os.makedirs(os.path.dirname(target_file),exist_ok=True)
                shutil.copyfile(changed_file,target_file)
print("sucess")




```

---  
---  
---  

# Youpk
又一款基于ART的主动调用的脱壳机



## 原理

Youpk是一款针对Dex整体加固+各式各样的Dex抽取的脱壳机

基本流程如下:

1. 从内存中dump DEX
2. 构造完整调用链, 主动调用所有方法并dump CodeItem
3. 合并 DEX, CodeItem

### 从内存中dump DEX

DEX文件在art虚拟机中使用DexFile对象表示, 而ClassLinker中引用了这些对象, 因此可以采用从ClassLinker中遍历DexFile对象并dump的方式来获取.

```c++
//unpacker.cc
std::list<const DexFile*> Unpacker::getDexFiles() {
  std::list<const DexFile*> dex_files;
  Thread* const self = Thread::Current();
  ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
  ReaderMutexLock mu(self, *class_linker->DexLock());
  const std::list<ClassLinker::DexCacheData>& dex_caches = class_linker->GetDexCachesData();
  for (auto it = dex_caches.begin(); it != dex_caches.end(); ++it) {
    ClassLinker::DexCacheData data = *it;
    const DexFile* dex_file = data.dex_file;
    dex_files.push_back(dex_file);
  }
  return dex_files;
}
```

另外, 为了避免dex做任何形式的优化影响dump下来的dex文件, 在dex2oat中设置 CompilerFilter 为仅验证

```c++
//dex2oat.cc
compiler_options_->SetCompilerFilter(CompilerFilter::kVerifyAtRuntime);
```



### 构造完整调用链, 主动调用所有方法

1. 创建脱壳线程

   ```java
   //unpacker.java
   public static void unpack() {
       if (Unpacker.unpackerThread != null) {
           return;
       }
   
       //开启线程调用
       Unpacker.unpackerThread = new Thread() {
           @Override public void run() {
               while (true) {
                   try {
                       Thread.sleep(UNPACK_INTERVAL);
                   }
                   catch (InterruptedException e) {
                       e.printStackTrace();
                   }
                   if (shouldUnpack()) {
                       Unpacker.unpackNative();
                   }   
               }
           }
       };
       Unpacker.unpackerThread.start();
   }
   ```

2. 在脱壳线程中遍历DexFile的所有ClassDef

   ```c++
   //unpacker.cc
   for (; class_idx < dex_file->NumClassDefs(); class_idx++) {
   ```

3. 解析并初始化Class

   ```c++
   //unpacker.cc
   mirror::Class* klass = class_linker->ResolveType(*dex_file, dex_file->GetClassDef(class_idx).class_idx_, h_dex_cache, h_class_loader);
   StackHandleScope<1> hs2(self);
   Handle<mirror::Class> h_class(hs2.NewHandle(klass));
   bool suc = class_linker->EnsureInitialized(self, h_class, true, true);
   ```

4. 主动调用Class的所有Method, 并修改ArtMethod::Invoke使其强制走switch型解释器

   ```c++
   //unpacker.cc
   uint32_t args_size = (uint32_t)ArtMethod::NumArgRegisters(method->GetShorty());
   if (!method->IsStatic()) {
       args_size += 1;
   }
   
   JValue result;
   std::vector<uint32_t> args(args_size, 0);
   if (!method->IsStatic()) {
       mirror::Object* thiz = klass->AllocObject(self);
       args[0] = StackReference<mirror::Object>::FromMirrorPtr(thiz).AsVRegValue();  
   }
   method->Invoke(self, args.data(), args_size, &result, method->GetShorty());
   
   //art_method.cc
   if (UNLIKELY(!runtime->IsStarted() || Dbg::IsForcedInterpreterNeededForCalling(self, this) 
   || (Unpacker::isFakeInvoke(self, this) && !this->IsNative()))) {
   if (IsStatic()) {
   art::interpreter::EnterInterpreterFromInvoke(
   self, this, nullptr, args, result, /*stay_in_interpreter*/ true);
   } else {
   mirror::Object* receiver =
   reinterpret_cast<StackReference<mirror::Object>*>(&args[0])->AsMirrorPtr();
   art::interpreter::EnterInterpreterFromInvoke(
   self, this, receiver, args + 1, result, /*stay_in_interpreter*/ true);
   }
   }
   
   //interpreter.cc
   static constexpr InterpreterImplKind kInterpreterImplKind = kSwitchImplKind;
   ```

5. 在解释器中插桩, 在每条指令执行前设置回调

   ```c++
   //interpreter_switch_impl.cc
   // Code to run before each dex instruction.
     #define PREAMBLE()                                                                 \
     do {                                                                               \
       inst_count++;                                                                    \
       bool dumped = Unpacker::beforeInstructionExecute(self, shadow_frame.GetMethod(), \
                                                        dex_pc, inst_count);            \
       if (dumped) {                                                                    \
         return JValue();                                                               \
       }                                                                                \
       if (UNLIKELY(instrumentation->HasDexPcListeners())) {                            \
         instrumentation->DexPcMovedEvent(self, shadow_frame.GetThisObject(code_item->ins_size_),  shadow_frame.GetMethod(), dex_pc);            						   										   \
       }                                                                                \
     } while (false)
   ```

6. 在回调中做针对性的CodeItem的dump, 这里仅仅是简单的示例了直接dump, 实际上, 针对某些厂商的抽取, 可以真正的执行几条指令等待CodeItem解密后再dump

   ```c++
   //unpacker.cc
   bool Unpacker::beforeInstructionExecute(Thread *self, ArtMethod *method, uint32_t dex_pc, int inst_count) {
     if (Unpacker::isFakeInvoke(self, method)) {
     	Unpacker::dumpMethod(method);
       return true;
     }
     return false;
   }
   ```



### 合并 DEX, CodeItem

将dump下来的CodeItem填充到DEX的相应位置中即可. 主要是基于google dx工具修改.



### 参考链接

FUPK3: https://bbs.pediy.com/thread-246117.htm

FART: https://bbs.pediy.com/thread-252630.htm



## 刷机

1. 仅支持pixel 1代
2. 重启至bootloader: `adb reboot bootloader`
3. 解压 Youpk_sailfish.zip 并双击 `flash-all.bat`



## 编译

### 脱壳机源码编译

1. 下载android-7.1.2_r33完整源码
2. 替换unpacker/android-7.1.2_r33
3. 编译

### 修复工具编译

1. IDEA导入dexfixer项目
2. main class为 `com.android.dx.unpacker.DexFixer` 



## 使用方法

1. **该工具仅仅用来学习交流, 请勿用于非法用途, 否则后果自付！**
   
2. 配置待脱壳的app包名, 准确来讲是进程名称

    ```bash
    adb shell "echo cn.youlor.mydemo >> /data/local/tmp/unpacker.config"
    ```

3. 如果apk没有整体加固, 未避免installd调用dex2oat优化, 需要在安装之前执行第2步
    
4. 启动apk等待脱壳
    每隔10秒将自动重新脱壳(已完全dump的dex将被忽略), 当日志打印unpack end时脱壳完成

5. pull出dump文件, dump文件路径为 `/data/data/包名/unpacker` 

    ```bash
    adb pull /data/data/cn.youlor.mydemo/unpacker
    ```

6. 调用修复工具 dexfixer.jar, 两个参数, 第一个为dump文件目录(必须为有效路径), 第二个为重组后的DEX目录(不存在将会创建)
    ```bash
    java -jar dexfixer.jar /path/to/unpacker /path/to/output
    ```



## 适用场景

1. 整体加固
2. 抽取:
   - nop占坑型(类似某加密)
   - naitve化, 在 `<clinit>` 中解密(类似早期阿里)
   - goto解密型(类似新版某加密, najia): https://bbs.pediy.com/thread-259448.htm




## 常见问题

1. dump中途退出或卡死，重新启动进程，再次等待脱壳即可
2. 当前仅支持被壳保护的dex, 不支持App动态加载的dex/jar
