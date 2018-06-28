


#define DEBUG
#ifdef DEBUG
#define DS1(fmt)														\
{																		\
	OutputDebugString(fmt);												\
}

#define DS2(fmt,fmt2)													\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s") ,fmt, fmt2);							\
	OutputDebugString(sOut);											\
}

#define DS3(fmt,fmt2,fmt3)												\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s%s") ,fmt, fmt2,fmt3);						\
	OutputDebugString(sOut);											\
}

#define DS2D1(fmt1,fmt2,dWord)											\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s%u"),fmt1,fmt2,dWord);						\
	OutputDebugString(sOut);											\
}

#define DS2D2(fmt1,fmt2,dWord1,fmt3,dWord2)								\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s%u%s%u"),fmt1,fmt2,dWord1,fmt3,dWord2);	\
	OutputDebugString(sOut);											\
}

#define DS2I1(fmt1,fmt2,Int)											\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s%d"),fmt1,fmt2,Int);						\
	OutputDebugString(sOut);											\
}
#define DS2X1(fmt1,fmt2,Hex)											\
{																		\
	TCHAR sOut[512];													\
	_stprintf(sOut,_T("%s->%s0X%08X"),fmt1,fmt2,Hex);					\
	OutputDebugString(sOut);											\
}


#else

#define DS1(fmt)	{;}	
#define DS2(fmt,fmt2)	{;}
#define DS3(fmt,fmt2,fmt3)		{;}	
#define DS2D1(fmt1,fmt2,Int)	{;}
#define DS2D2(fmt1,fmt2,dWord1,fmt3,dWord2)	{;}
#define DS2I1(fmt1,fmt2,dWord)	{;}
#define DS2X1(fmt1,fmt2,Hex)	{;}
#endif

