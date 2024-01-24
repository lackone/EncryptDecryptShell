#include "PETools.h"

/**
 * 读取PE文件到内存中，返回值为读取到的字节数
 * filePath 文件路径
 * fileBuffer 读取到的内存buffer
 */
DWORD PETools::ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer)
{
	//打开文件
	LPSTR str = NULL;
	TCHARToChar(filePath, &str);

	FILE* fp;
	if (fopen_s(&fp, str, "rb") != 0)
	{
		return 0;
	}

	//获取文件的大小
	fseek(fp, 0, SEEK_END);
	DWORD fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//申请内存
	LPVOID fBuf = malloc(fileSize);
	if (fBuf == NULL)
	{
		fclose(fp);
		return 0;
	}

	//读取数据到申请的内存中
	memset(fBuf, 0, fileSize);
	fread(fBuf, fileSize, 1, fp);

	*pFileBuffer = fBuf;

	//关闭文件，返回文件大小
	fclose(fp);

	free(str);

	return fileSize;
}

/**
 * 将内存偏移转换为文件偏移
 * pFileBuffer 文件buffer
 * dwRva 内存偏移
 */
DWORD PETools::RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;
	PIMAGE_SECTION_HEADER section;

	dos = (PIMAGE_DOS_HEADER)pFileBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = (PIMAGE_SECTION_HEADER)((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//如果RVA小于头部大小，直接返回RVA，因为文件和拉伸后的，头部并不会变
	//如果文件对齐与内存对齐一样，则文件和拉伸后的，也不会变
	if (dwRva < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwRva;
	}

	//遍历节，判断RVA在哪个节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		//判断RVA哪个节
		if (dwRva >= section->VirtualAddress && dwRva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return section->PointerToRawData + (dwRva - section->VirtualAddress);
		}
		section++;
	}

	return 0;
}

/**
 * 将文件偏移转换为内存偏移
 * pFileBuffer 文件buffer
 * dwFoa 文件偏移
 */
DWORD PETools::FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS32 nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER32 opt;
	PIMAGE_SECTION_HEADER section;

	dos = (PIMAGE_DOS_HEADER)pFileBuffer;
	nt = (PIMAGE_NT_HEADERS32)((LPBYTE)dos + dos->e_lfanew);
	pe = (PIMAGE_FILE_HEADER)((LPBYTE)nt + 4);
	opt = (PIMAGE_OPTIONAL_HEADER32)((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = (PIMAGE_SECTION_HEADER)((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//如果FOA小于头部大小，直接返回FOA，因为文件和拉伸后的，头部并不会变
	//如果文件对齐与内存对齐一样，则文件和拉伸后的，也不会变
	if (dwFoa < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwFoa;
	}

	//遍历节，判断FOA在哪个节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		if (dwFoa >= section->PointerToRawData && dwFoa < section->PointerToRawData + section->SizeOfRawData)
		{
			return section->VirtualAddress + (dwFoa - section->PointerToRawData);
		}
		section++;
	}

	return 0;
}

/**
 * 字节对齐
 */
DWORD PETools::Align(IN DWORD x, IN DWORD y)
{
	if (x % y == 0)
	{
		return x;
	}
	else
	{
		DWORD n = x / y;
		return (n + 1) * y;
	}
}

/**
 * 保存文件
 * pFileBuffer 文件buffer
 * fileSize 文件大小
 * filePath 文件路径
 */
DWORD PETools::SaveFile(IN LPVOID pFileBuffer, IN DWORD fileSize, IN LPCTSTR filePath)
{
	LPSTR str = NULL;
	TCHARToChar(filePath, &str);

	FILE* fp;
	if (fopen_s(&fp, str, "wb+") != 0)
	{
		return 0;
	}
	fwrite(pFileBuffer, fileSize, 1, fp);
	fclose(fp);
	free(str);
	return fileSize;
}

/**
 * 添加节
 * pFileBuffer 文件buffer
 * fileSize 文件大小
 * addSize 添加节大小
 * addName 添加节名称
 * pNewFileBuffer 添加节后新生成的文件buffer
 */
DWORD PETools::AddSection(IN LPVOID pFileBuffer, IN DWORD fileSize, IN DWORD addSize, IN LPCTSTR addName, OUT LPVOID* pNewFileBuffer)
{
	LPSTR str = NULL;
	TCHARToChar(addName, &str);

	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//整个PE头的大小减去，e_lfanew偏移 + 4字节的Signature + 20字节的标准PE头 + 可选PE头大小 + 节表数量*40字节的节表
	//如果剩余的空间大于2个节表的大小，那么节就可以添加，一般情况下都是可以添加的。
	//为什么要大于2个节表，因为1个是我们自已要添加的，另1个是我们要进行填充0，说白了就是用0结尾。
	if ((opt->SizeOfHeaders - (dos->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pe->SizeOfOptionalHeader + pe->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER)) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		return 0;
	}

	//添加的大小使用文件对齐，后面会用到
	DWORD addSectionSize = Align(addSize, opt->FileAlignment);

	//镜像大小必须SectionAlignment对齐
	DWORD imageSize = Align(opt->SizeOfImage + addSize, opt->SectionAlignment);

	//申请内存
	LPVOID buf = malloc(imageSize);
	if (buf == NULL)
	{
		return 0;
	}

	//内存置为0，并把原来pFileBuffer文件中的数据，全部复制到新申请的内存buf中
	memset(buf, 0, imageSize);
	memcpy(buf, pFileBuffer, fileSize);

	//注意，这里的变量指向变了，原先指向的是pFileBuffer，现在指向的是buf
	dos = PIMAGE_DOS_HEADER(buf);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//复制第一个节表到新节
	//现在的section指向第一个节表，section + pe->NumberOfSections表示在最后一个节的结束的位置，也就是我们新节开始的位置
	memcpy(section + pe->NumberOfSections, section, IMAGE_SIZEOF_SECTION_HEADER);

	//在新节后面再设置一个节，全部置为0
	//这里就是上面为什么要判断大于2个节表的原因
	memset(section + pe->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	//指向最后一个节
	PIMAGE_SECTION_HEADER last_section = section + pe->NumberOfSections;
	//指向最后一个节的前一个节
	PIMAGE_SECTION_HEADER last_pre_section = last_section - 1;

	//修改PE文件节的数量，原数量+1
	pe->NumberOfSections += 1;

	//把节名称，复制到Name中
	memcpy(last_section->Name, str, strlen(str) + 1);

	//注意这里要对齐，很关键，很关键
	//最后一个节的文件偏移 = 前一个节的文件偏移 + 前一个节对齐FileAlignment后的节大小
	last_section->PointerToRawData = last_pre_section->PointerToRawData + Align(last_pre_section->SizeOfRawData, opt->FileAlignment);

	//SizeOfRawData要按FileAlignment对齐
	//前面为什么addSectionSize要用FileAlignment对齐的原因，这里要用
	last_section->SizeOfRawData = addSectionSize;

	//注意这里要对齐，很关键，很关键
	//最后一个节的内存偏移 = 前一个节的内存偏移 + 前一个节对齐SectionAlignment后的节大小
	last_section->VirtualAddress = last_pre_section->VirtualAddress + Align(max(last_pre_section->SizeOfRawData, last_pre_section->Misc.VirtualSize), opt->SectionAlignment);
	last_section->Misc.VirtualSize = addSectionSize;

	//注意注入时，这里的属性一定要有0xC0000040
	last_section->Characteristics = 0xE0000060;

	//注意这里要对齐，很关键，很关键
	//SizeOfImage要按SectionAlignment对齐
	opt->SizeOfImage = imageSize;

	*pNewFileBuffer = buf;

	free(str);

	return imageSize;
}

/**
 * 拉升文件buffer为imageBuffer
 * pFileBuffer 文件buffer
 * pImageBuffer 拉伸后的buffer
 */
DWORD PETools::FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//1、先申请sizeOfImage的空间
	LPVOID imgBuf = malloc(opt->SizeOfImage);
	if (imgBuf == NULL)
	{
		return 0;
	}
	memset(imgBuf, 0, opt->SizeOfImage);

	//2、拷贝头数据
	memcpy(imgBuf, pFileBuffer, opt->SizeOfHeaders);

	//3、遍历拷贝节
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		memcpy((LPBYTE)imgBuf + section->VirtualAddress, (LPBYTE)pFileBuffer + section->PointerToRawData, max(section->SizeOfRawData, section->Misc.VirtualSize));
		section++;
	}

	*pImageBuffer = imgBuf;

	return opt->SizeOfImage;
}

/**
 * 修正重定位表
 */
VOID PETools::ReviseRelocation(IN LPVOID pFileBuffer, IN DWORD offset)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_SECTION_HEADER last_section;
	IMAGE_DATA_DIRECTORY* dir;


	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);
	last_section = section + pe->NumberOfSections - 1;
	dir = opt->DataDirectory;

	DWORD relFoa = RvaToFoa(pFileBuffer, dir[5].VirtualAddress);

	PIMAGE_BASE_RELOCATION relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pFileBuffer + relFoa);

	while (relDir->SizeOfBlock && relDir->VirtualAddress)
	{
		int nums = (relDir->SizeOfBlock - 8) / 2;

		LPWORD start = LPWORD((LPBYTE)relDir + 8);

		for (int i = 0; i < nums; i++)
		{
			WORD type = ((*start) & 0xF000) >> 12;

			if (type == 3)
			{
				//VirtualAddress+后12位，才是真正的RVA
				DWORD rva = relDir->VirtualAddress + ((*start) & 0x0FFF);

				LPDWORD addr = LPDWORD((LPBYTE)pFileBuffer + RvaToFoa(pFileBuffer, rva));

				*addr = *addr + offset;
			}

			start++;
		}

		relDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)relDir + relDir->SizeOfBlock);
	}
}

/**
 * 将TCHAR转换成CHAR
 */
VOID PETools::TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str)
{
	int size_needed = WideCharToMultiByte(CP_ACP, 0, tstr, -1, NULL, 0, NULL, NULL);
	LPSTR buf = (LPSTR)malloc(sizeof(CHAR) * size_needed);
	WideCharToMultiByte(CP_ACP, 0, tstr, -1, buf, size_needed, NULL, NULL);
	*str = buf;
}

/**
 * 加密，最简单的异或
 */
VOID PETools::Encrypt(IN LPVOID pFileBuffer, IN DWORD fileSize)
{
	LPBYTE tmp = (LPBYTE)pFileBuffer;
	for (int i = 0; i < fileSize; i++)
	{
		tmp[i] = tmp[i] ^ key[i % 7];
	}
}

/**
 * 解密，最简单的异或
 */
VOID PETools::Decrypt(IN LPVOID pFileBuffer, IN DWORD fileSize)
{
	LPBYTE tmp = (LPBYTE)pFileBuffer;
	for (int i = 0; i < fileSize; i++)
	{
		tmp[i] = tmp[i] ^ key[i % 7];
	}
}

/**
 * 获取最后一个节
 */
PIMAGE_SECTION_HEADER PETools::GetLastSection(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;
	PIMAGE_SECTION_HEADER section;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	return section + (pe->NumberOfSections - 1);
}

/**
 * 获取可选PE头
 */
PIMAGE_OPTIONAL_HEADER PETools::GetOptionHeader(IN LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_FILE_HEADER pe;
	PIMAGE_OPTIONAL_HEADER opt;

	dos = PIMAGE_DOS_HEADER(pFileBuffer);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);

	return opt;
}