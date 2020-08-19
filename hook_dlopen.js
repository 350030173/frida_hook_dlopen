/*
用法：
frida -U -l hook_dlopen.js -f packageName --no-pause

*/


//soName传入指定.so
//offset偏移
var is_can_hook = false;
function hook_dlopen(soName,offset)
{
	Interceptor.attach(Module.findExportByName(null, "dlopen"),
	{
		onEnter: function (args)
		{
			var pathptr = args[0];
			if (pathptr !== undefined && pathptr != null)
			{
				var path = ptr(pathptr).readCString();
				//console.log("dlopen:", path);
				if (path.indexOf(soName) >= 0)
				{
					//找到指定.so后，在onLeave就可以hook到，而不是在onEnter里hook指定.so
					this.is_can_hook = true;
					console.log("\n"+soName+"_address:", path);

				}
			}
		},
		onLeave: function (retval)
		{
			if (this.is_can_hook)
			{
				var moduleBaseAddress = Module.getBaseAddress(soName);
				console.log(soName + "_address:", moduleBaseAddress);
				var nativePointer = moduleBaseAddress.add(offset);//加上偏移地址，hook指定函数
				Interceptor.attach(nativePointer,
				{
					onEnter: function (args)
					{
						console.log("==参数1：" + args[0]); 
						console.log("==参数2的key：" + ptr(args[1]).readCString())	
					},
					onLeave: function (retval)
					{
						console.log("hook function finish..."); 
					}
				}
				);
				console.log("dlopen finish...");
			}
		}
	}
	);

	Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
	{
		onEnter: function (args)
		{
			var pathptr = args[0];
			if (pathptr !== undefined && pathptr != null)
			{
				var path = ptr(pathptr).readCString();
				//console.log("android_dlopen_ext:", path);
				
				if (path.indexOf(soName) >= 0)
				{
					//找到指定.so后，在onLeave就可以hook到，而不是在onEnter里hook指定.so
					this.is_can_hook = true;
					console.log("\n"+soName+"_path:", path);
				}
			}
		},
		onLeave: function (retval)
		{
			if (this.is_can_hook)
			{
				var moduleBaseAddress = Module.getBaseAddress(soName);
				console.log(soName + "_address:", moduleBaseAddress);
				var nativePointer = moduleBaseAddress.add(offset);//加上偏移地址，hook指定函数
				Interceptor.attach(nativePointer,
				{
					onEnter: function (args)
					{
						console.log("==参数1：" + args[0]); 
						console.log("==参数2的key：" + ptr(args[1]).readCString())	
					},
					onLeave: function (retval)
					{
						console.log("ext hook function finish..."); 
					}
				}
				);
				console.log("android_dlopen_ext  finish...");
			}
			
		}
	}
	);
}

setImmediate(hook_dlopen("libcocos2djs.so",0x6E1AE4));
