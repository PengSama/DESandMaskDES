(function(){
	/*
	 *message,key都为16进制的形式的字符串，如'4c8ed9b32bac33dc'，表示一组64位的明文
	 *函数式编程
	 *对DES算法中间值进行掩码处理，能随机化功耗信息，达到抗差分功耗攻击
	 */
	function maskDES(message,key,random){
		generateRandom(turnTo64bits(random))
		return turnToBase16(IP_1boxTrans(encrpty(IPboxTrans(turnTo64bits(message)),generateKeys(turnTo64bits(key)))))
	}
const		IP=[58,50,42,34,26,18,10,2,
			60,52,44,36,28,20,12,4,
			62,54,46,38,30,22,14,6,
			64,56,48,40,32,24,16,8,
			57,49,41,33,25,17,9,1,
			59,51,43,35,27,19,11,3,
			61,53,45,37,29,21,13,5,
			63,55,47,39,31,23,15,7],
		IP_1=[40,8,48,16,56,24,64,32,
			39,7,47,15,55,23,63,31,
			38,6,46,14,54,22,62,30,
			37,5,45,13,53,21,61,29,
			36,4,44,12,52,20,60,28,
			35,3,43,11,51,19,59,27,
			34,2,42,10,50,18,58,26,
			33,1,41,9,49,17,57,25],
		E=[32,1,2,3,4,5,
			4,5,6,7,8,9,
			8,9,10,11,12,13,
			12,13,14,15,16,17,
			16,17,18,19,20,21,
			20,21,22,23,24,25,
			24,25,26,27,28,29,
			28,29,30,31,32,1],
		S1=[[14,04,13,01,02,15,11,08,03,10,06,12,05,09,00,07],
			[00,15,07,04,14,02,13,01,10,06,12,11,09,05,03,08],
			[04,01,14,08,13,06,02,11,15,12,09,07,03,10,05,00],
			[15,12,08,02,04,09,01,07,05,11,03,14,10,00,06,13]
			],
		S2=[[15,01,08,14,06,11,03,04,09,07,02,13,12,00,05,10],
			[03,13,04,07,15,02,08,14,12,00,01,10,06,09,11,05],
			[00,14,07,11,10,04,13,01,05,08,12,06,09,03,02,15],
			[13,08,10,01,03,15,04,02,11,06,07,12,00,05,14,09]
			],
		S3=[[10,00,09,14,06,03,15,05,01,13,12,07,11,04,02,08],
			[13,07,00,09,03,04,06,10,02,08,05,14,12,11,15,01],
			[13,06,04,09,08,15,03,00,11,01,02,12,05,10,14,07],
			[01,10,13,00,06,09,08,07,04,15,14,03,11,05,12,12]
			],
		S4=[[07,13,14,03,00,06,09,10,01,02,08,05,11,12,04,15],
			[13,08,11,05,06,15,00,03,04,07,02,12,01,10,14,09],
			[10,06,09,00,12,11,07,13,15,01,03,14,05,02,08,04],
			[03,15,00,06,10,01,13,08,09,04,05,11,12,07,02,14]
			],
		S5=[[02,12,04,01,07,10,11,06,08,05,03,15,13,00,14,09],
			[14,11,02,12,04,07,13,01,05,00,15,10,03,09,08,06],
			[04,02,01,11,10,13,07,08,15,09,12,05,15,03,00,14],
			[11,08,12,07,01,14,02,13,06,15,00,09,10,04,05,03]
			],
		S6=[[12,01,10,15,09,02,06,08,00,13,03,04,14,07,05,11],
			[10,15,04,02,07,12,09,05,06,01,13,14,00,11,03,08],
			[09,14,15,05,02,08,12,03,07,00,04,10,01,13,11,06],
			[04,03,02,12,09,05,15,10,11,14,01,07,06,00,08,13]
			],
		S7=[[04,11,02,14,15,00,08,13,03,12,09,07,05,10,06,01],
			[13,00,11,07,04,09,01,10,14,03,05,12,02,15,08,06],
			[01,04,11,13,12,03,07,14,10,15,06,08,00,05,09,02],
			[06,11,13,08,01,04,10,07,09,05,00,15,14,02,03,12]
			],
		S8=[[13,02,08,04,06,15,11,01,10,09,03,14,05,00,12,07],
			[01,15,13,08,10,03,07,04,12,05,06,11,00,14,09,02],
			[07,11,04,01,09,12,14,02,00,06,10,13,15,03,05,08],
			[02,01,14,07,04,10,08,13,15,12,09,00,03,05,06,11]
			],
		P=[16,7,20,21,29,12,28,17,
			1,15,23,26,5,18,31,10,
			2,8,24,14,32,27,3,9,
			19,13,30,6,22,11,4,25]
		PC_1=[57,49,41,33,25,17,9,1,
			58,50,42,34,26,18,10,2,
			59,51,43,35,27,19,11,3,
			60,52,44,36,63,55,47,39,
			31,23,15,7,62,54,46,38,
			30,22,14,6,61,53,45,37,
			29,21,13,5,28,20,12,4],
		PC_2=[14,17,11,24,1,5,3,28,
			15,6,21,10,23,19,12,4,
			26,8,16,7,27,20,13,2,
			41,52,31,37,47,55,30,40,
			51,45,33,48,44,49,39,56,
			34,53,46,42,50,36,29,32]
		base16to2={
			'0':'0000','1':'0001','2':'0010','3':'0011',
			'4':'0100','5':'0101','6':'0110','7':'0111',
			'8':'1000','9':'1001','a':'1010','b':'1011',
			'c':'1100','d':'1101','e':'1110','f':'1111',
			'A':'1010','B':'1011','C':'1100','D':'1101',
			'E':'1110','F':'1111','10':'1010','11':'1011',
			'12':'1100','13':'1101','14':'1110','15':'1111'
				}
		base2to16={
			'0000':'0','0001':'1','0010':'2','0011':'3',
			'0100':'4','0101':'5','0110':'6','0111':'7',
			'1000':'8','1001':'9','1010':'a','1011':'b',
			'1100':'c','1101':'d','1110':'e','1111':'f'
				}
	var X1,X2,X3,X4,X5,X6
	function turnToBase16(str){
		let output=''
		for(let i=0;i<64;i=i+4){
			output+=base2to16[str.slice(i,i+4)]
		}
		return output
	}
	//在匿名函数作用域中产生X1,X2,X3,X4,X5,X6随机数
	function generateRandom(random){
		X1=random.slice(0,32)
		X2=random.slice(32)
		X3=PboxTrans(X2)
		X4=PboxTrans(X1)
		X5=XOR32(X3,X4)
		X6=EboxTrans(X3)
	}
	function XOR32(str1,str2){
		let str=''
		for(let i=0;i<32;i++){
			str+=str1[i]^str2[i]
		}
		return str
	}
	function XOR48(str1,str2){
		let str=''
		for(let i=0;i<48;i++){
			str+=str1[i]^str2[i]
		}
		return str
	}
	//对不同轮数的DES算法加密进行不同处理
	function encrpty(messages,keys){
		let i=0
		while(i<16){
			if(i===0){
				messages=firstEncrypt(messages,keys[i])
			}else if(i===15){
				messages=lastEncrypt(messages,keys[i])
			}else{
				messages=oneEncrypt(messages,keys[i])
			}
			i++
		}
		return messages.slice(32)+messages.slice(0,32)
	}
	function turnTo64bits(str){
		let output=''
		for(let i=0;i<str.length;i++){
			output+=base16to2[str[i]]
		}
		return output
	}
	//密钥产生函数
	function generateKeys(key){
		let PC=PC_1boxTrans(key)
		let C=PC.slice(0,28)
		let D=PC.slice(28)
		let keys=[]
		for(let i=1;i<=16;i++){
			if(i===1 || i===2 || i===9 || i===16){
				C.push(C.shift())
				D.push(D.shift())
				keys[i-1]=PC_2boxTrans(C,D)
			}else{
				C.push(C.shift())
				C.push(C.shift())
				D.push(D.shift())
				D.push(D.shift())
				keys[i-1]=PC_2boxTrans(C,D)
			}
		}
		return keys
	}
	//密钥编排PC-1置换
	function PC_1boxTrans(key){
		let arr=[]
		for(let i=0;i<56;i++){
			arr.push(key[PC_1[i]-1])
		}
		return arr
	}
	//密钥编排PC-2置换
	function PC_2boxTrans(C,D){
		let temp=C.join('')+D.join('')
		let str=''
		for(let i=0;i<48;i++){
			str+=temp[PC_2[i]-1]
		}
		return str
	}
	//首轮加密时处理函数
	function firstEncrypt(str,key){
		let left=str.slice(0,32)
		let right=str.slice(32)
		return XOR32(right,X4)+XOR32(PboxTrans(XOR32(SboxSearch(XOR48(EboxTrans(right),key)),X2)),left)
	}
	//末轮加密时处理函数
	function lastEncrypt(str,key){
		let left=str.slice(0,32)
		let right=str.slice(32)
		return XOR32(right,X3)+XOR32(XOR32(PboxTrans(maskSboxSearch(XOR48(EboxTrans(right),key))),left),X3)
	}
	//中间轮加密时处理函数
	function oneEncrypt(str,key){
		let left=str.slice(0,32)
		let right=str.slice(32)
		return XOR32(right,X5)+XOR32(PboxTrans(maskSboxSearch(XOR48(EboxTrans(right),key))),left)
	}
	//初始IP置换
	function IPboxTrans(message){
		let str=''
		for(let i=0;i<64;i++){
			str+=message[IP[i]-1]
		}
		return str
	}
	//输出密文前的逆IP置换
	function IP_1boxTrans(message){
		let str=''
		for(let i=0;i<64;i++){
			str+=message[IP_1[i]-1]
		}
		return str
	}
	//E盒置换
	function EboxTrans(str){
		let output=''
		for(let i=0;i<48;i++){
			output+=str[E[i]-1]
		}
		return output
	}
	//掩码DES算法改进后的S盒查找
	function maskSboxSearch(str){
		return XOR32(XOR32(SboxSearch(XOR48(str,X6)),X1),X2)
	}
	function SboxSearch(str){
		let cols=[]
		let rows=[]
		let i=0
		while(i<48){
			cols.push(parseInt((str[i]+str[i+5]),2))
			rows.push(parseInt(str.slice(i+1,i+5),2))
			i+=6
		}
		return  base16to2[S1[cols[0]][rows[0]]]+
				base16to2[S2[cols[1]][rows[1]]]+
				base16to2[S3[cols[2]][rows[2]]]+
				base16to2[S4[cols[3]][rows[3]]]+
				base16to2[S5[cols[4]][rows[4]]]+
				base16to2[S6[cols[5]][rows[5]]]+
				base16to2[S7[cols[6]][rows[6]]]+
				base16to2[S8[cols[7]][rows[7]]]

	}
	//P盒置换
	function PboxTrans(str){
		let output=''
		for(let i=0;i<32;i++){
			output+=str[P[i]-1]
		}
		return output
	}
	window.maskDES=maskDES
})()
maskDES('4c8ed9b32bac33dc','0123456789abcdef','2178361721783617')