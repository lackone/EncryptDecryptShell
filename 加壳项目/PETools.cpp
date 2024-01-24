#include "PETools.h"

/**
 * ��ȡPE�ļ����ڴ��У�����ֵΪ��ȡ�����ֽ���
 * filePath �ļ�·��
 * fileBuffer ��ȡ�����ڴ�buffer
 */
DWORD PETools::ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer)
{
	//���ļ�
	LPSTR str = NULL;
	TCHARToChar(filePath, &str);

	FILE* fp;
	if (fopen_s(&fp, str, "rb") != 0)
	{
		return 0;
	}

	//��ȡ�ļ��Ĵ�С
	fseek(fp, 0, SEEK_END);
	DWORD fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//�����ڴ�
	LPVOID fBuf = malloc(fileSize);
	if (fBuf == NULL)
	{
		fclose(fp);
		return 0;
	}

	//��ȡ���ݵ�������ڴ���
	memset(fBuf, 0, fileSize);
	fread(fBuf, fileSize, 1, fp);

	*pFileBuffer = fBuf;

	//�ر��ļ��������ļ���С
	fclose(fp);

	free(str);

	return fileSize;
}

/**
 * ���ڴ�ƫ��ת��Ϊ�ļ�ƫ��
 * pFileBuffer �ļ�buffer
 * dwRva �ڴ�ƫ��
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

	//���RVAС��ͷ����С��ֱ�ӷ���RVA����Ϊ�ļ��������ģ�ͷ���������
	//����ļ��������ڴ����һ�������ļ��������ģ�Ҳ�����
	if (dwRva < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwRva;
	}

	//�����ڣ��ж�RVA���ĸ���
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		//�ж�RVA�ĸ���
		if (dwRva >= section->VirtualAddress && dwRva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return section->PointerToRawData + (dwRva - section->VirtualAddress);
		}
		section++;
	}

	return 0;
}

/**
 * ���ļ�ƫ��ת��Ϊ�ڴ�ƫ��
 * pFileBuffer �ļ�buffer
 * dwFoa �ļ�ƫ��
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

	//���FOAС��ͷ����С��ֱ�ӷ���FOA����Ϊ�ļ��������ģ�ͷ���������
	//����ļ��������ڴ����һ�������ļ��������ģ�Ҳ�����
	if (dwFoa < opt->SizeOfHeaders || opt->FileAlignment == opt->SectionAlignment)
	{
		return dwFoa;
	}

	//�����ڣ��ж�FOA���ĸ���
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
 * �ֽڶ���
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
 * �����ļ�
 * pFileBuffer �ļ�buffer
 * fileSize �ļ���С
 * filePath �ļ�·��
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
 * ��ӽ�
 * pFileBuffer �ļ�buffer
 * fileSize �ļ���С
 * addSize ��ӽڴ�С
 * addName ��ӽ�����
 * pNewFileBuffer ��ӽں������ɵ��ļ�buffer
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

	//����PEͷ�Ĵ�С��ȥ��e_lfanewƫ�� + 4�ֽڵ�Signature + 20�ֽڵı�׼PEͷ + ��ѡPEͷ��С + �ڱ�����*40�ֽڵĽڱ�
	//���ʣ��Ŀռ����2���ڱ�Ĵ�С����ô�ھͿ�����ӣ�һ������¶��ǿ�����ӵġ�
	//ΪʲôҪ����2���ڱ���Ϊ1������������Ҫ��ӵģ���1��������Ҫ�������0��˵���˾�����0��β��
	if ((opt->SizeOfHeaders - (dos->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pe->SizeOfOptionalHeader + pe->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER)) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		return 0;
	}

	//��ӵĴ�Сʹ���ļ����룬������õ�
	DWORD addSectionSize = Align(addSize, opt->FileAlignment);

	//�����С����SectionAlignment����
	DWORD imageSize = Align(opt->SizeOfImage + addSize, opt->SectionAlignment);

	//�����ڴ�
	LPVOID buf = malloc(imageSize);
	if (buf == NULL)
	{
		return 0;
	}

	//�ڴ���Ϊ0������ԭ��pFileBuffer�ļ��е����ݣ�ȫ�����Ƶ���������ڴ�buf��
	memset(buf, 0, imageSize);
	memcpy(buf, pFileBuffer, fileSize);

	//ע�⣬����ı���ָ����ˣ�ԭ��ָ�����pFileBuffer������ָ�����buf
	dos = PIMAGE_DOS_HEADER(buf);
	nt = PIMAGE_NT_HEADERS((LPBYTE)dos + dos->e_lfanew);
	pe = PIMAGE_FILE_HEADER((LPBYTE)nt + 4);
	opt = PIMAGE_OPTIONAL_HEADER((LPBYTE)pe + IMAGE_SIZEOF_FILE_HEADER);
	section = PIMAGE_SECTION_HEADER((LPBYTE)opt + pe->SizeOfOptionalHeader);

	//���Ƶ�һ���ڱ��½�
	//���ڵ�sectionָ���һ���ڱ�section + pe->NumberOfSections��ʾ�����һ���ڵĽ�����λ�ã�Ҳ���������½ڿ�ʼ��λ��
	memcpy(section + pe->NumberOfSections, section, IMAGE_SIZEOF_SECTION_HEADER);

	//���½ں���������һ���ڣ�ȫ����Ϊ0
	//�����������ΪʲôҪ�жϴ���2���ڱ��ԭ��
	memset(section + pe->NumberOfSections + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);

	//ָ�����һ����
	PIMAGE_SECTION_HEADER last_section = section + pe->NumberOfSections;
	//ָ�����һ���ڵ�ǰһ����
	PIMAGE_SECTION_HEADER last_pre_section = last_section - 1;

	//�޸�PE�ļ��ڵ�������ԭ����+1
	pe->NumberOfSections += 1;

	//�ѽ����ƣ����Ƶ�Name��
	memcpy(last_section->Name, str, strlen(str) + 1);

	//ע������Ҫ���룬�ܹؼ����ܹؼ�
	//���һ���ڵ��ļ�ƫ�� = ǰһ���ڵ��ļ�ƫ�� + ǰһ���ڶ���FileAlignment��Ľڴ�С
	last_section->PointerToRawData = last_pre_section->PointerToRawData + Align(last_pre_section->SizeOfRawData, opt->FileAlignment);

	//SizeOfRawDataҪ��FileAlignment����
	//ǰ��ΪʲôaddSectionSizeҪ��FileAlignment�����ԭ������Ҫ��
	last_section->SizeOfRawData = addSectionSize;

	//ע������Ҫ���룬�ܹؼ����ܹؼ�
	//���һ���ڵ��ڴ�ƫ�� = ǰһ���ڵ��ڴ�ƫ�� + ǰһ���ڶ���SectionAlignment��Ľڴ�С
	last_section->VirtualAddress = last_pre_section->VirtualAddress + Align(max(last_pre_section->SizeOfRawData, last_pre_section->Misc.VirtualSize), opt->SectionAlignment);
	last_section->Misc.VirtualSize = addSectionSize;

	//ע��ע��ʱ�����������һ��Ҫ��0xC0000040
	last_section->Characteristics = 0xE0000060;

	//ע������Ҫ���룬�ܹؼ����ܹؼ�
	//SizeOfImageҪ��SectionAlignment����
	opt->SizeOfImage = imageSize;

	*pNewFileBuffer = buf;

	free(str);

	return imageSize;
}

/**
 * �����ļ�bufferΪimageBuffer
 * pFileBuffer �ļ�buffer
 * pImageBuffer ������buffer
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

	//1��������sizeOfImage�Ŀռ�
	LPVOID imgBuf = malloc(opt->SizeOfImage);
	if (imgBuf == NULL)
	{
		return 0;
	}
	memset(imgBuf, 0, opt->SizeOfImage);

	//2������ͷ����
	memcpy(imgBuf, pFileBuffer, opt->SizeOfHeaders);

	//3������������
	for (int i = 0; i < pe->NumberOfSections; i++)
	{
		memcpy((LPBYTE)imgBuf + section->VirtualAddress, (LPBYTE)pFileBuffer + section->PointerToRawData, max(section->SizeOfRawData, section->Misc.VirtualSize));
		section++;
	}

	*pImageBuffer = imgBuf;

	return opt->SizeOfImage;
}

/**
 * �����ض�λ��
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
				//VirtualAddress+��12λ������������RVA
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
 * ��TCHARת����CHAR
 */
VOID PETools::TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str)
{
	int size_needed = WideCharToMultiByte(CP_ACP, 0, tstr, -1, NULL, 0, NULL, NULL);
	LPSTR buf = (LPSTR)malloc(sizeof(CHAR) * size_needed);
	WideCharToMultiByte(CP_ACP, 0, tstr, -1, buf, size_needed, NULL, NULL);
	*str = buf;
}

/**
 * ���ܣ���򵥵����
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
 * ���ܣ���򵥵����
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
 * ��ȡ���һ����
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
 * ��ȡ��ѡPEͷ
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