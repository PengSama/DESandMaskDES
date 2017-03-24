# DESandMaskDES
	DES-functional.js和Mask-functional.js都是函数式编程。
	DES-functional.js添加了解密功能，而Mask-functional.js没有，使用像DES('4c8ed9b32bac33dc','0123456789abcdef')来加密，第一个参数是需要加密的64位明文，用了16进制表示，第二个参数为64位密文，也是用16进制表示。如需使用解密功能，则添加第三个参数DES('4c8ed9b32bac33dc','0123456789abcdef','unencrpty').
