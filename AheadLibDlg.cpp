
// AheadLibDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "AheadLib.h"
#include "AheadLibDlg.h"
#include "afxdialogex.h"

#include "AheadSource.h"

#define AHEADLIB_VERSION _T("AheadLib x86/x64  Ver:1.2")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CAheadLibDlg 对话框


CAheadLibDlg::CAheadLibDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_AHEADLIB_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAheadLibDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_SHOW, m_show);
	DDX_Control(pDX, IDC_STATIC_NAMESTRING, m_NameString);
	DDX_Control(pDX, IDC_STATIC_ARCH, m_Arch);
	DDX_Control(pDX, IDC_STATIC_TIMESTAMP, m_Timestamp);
	DDX_Control(pDX, IDC_EDIT_INPUTFILE, m_InputFile);
	DDX_Control(pDX, IDC_EDIT_OUTPUTFILE, m_OutputFile);
}

BEGIN_MESSAGE_MAP(CAheadLibDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_EXIT, &CAheadLibDlg::OnBnClickedButtonExit)
	ON_BN_CLICKED(IDC_BUTTON_MAKEFILE, &CAheadLibDlg::OnBnClickedButtonMakefile)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON_CHOSEFILE, &CAheadLibDlg::OnBnClickedButtonChosefile)
	ON_BN_CLICKED(IDC_BUTTON_SAVEFILE, &CAheadLibDlg::OnBnClickedButtonSavefile)
END_MESSAGE_MAP()



/*
 *	禁止目录重定向
 */
BOOL safeWow64DisableDirectory(PVOID &arg)
{
	typedef BOOL WINAPI fntype_Wow64DisableWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64DisableWow64FsRedirection = (fntype_Wow64DisableWow64FsRedirection*)\
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64DisableWow64FsRedirection");

	if (pfnWow64DisableWow64FsRedirection) {

		(*pfnWow64DisableWow64FsRedirection)(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/*
 *	恢复目录重定向
 */
BOOL safeWow64ReverDirectory(PVOID &arg)
{
	typedef BOOL WINAPI fntype_Wow64RevertWow64FsRedirection(PVOID *OldValue);
	auto pfnWow64RevertWow64FsRedirection = (fntype_Wow64RevertWow64FsRedirection*) \
		GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64RevertWow64FsRedirection");

	if (pfnWow64RevertWow64FsRedirection) {

		(*pfnWow64RevertWow64FsRedirection)(&arg);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/*
 *	安全取得系统真实信息
 */
VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
	if (NULL == lpSystemInfo)    return;
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = \
		(LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32"), "GetNativeSystemInfo");

	if (NULL != fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(lpSystemInfo);
	}
	else
	{
		GetSystemInfo(lpSystemInfo);
	}
}

/**
 * 获取系统位数
 */
BOOL IsArch64()
{
	SYSTEM_INFO si;
 	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		return TRUE;
	}

	return FALSE;
}

// CAheadLibDlg 消息处理程序

BOOL CAheadLibDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	PVOID redir;

	SetWindowText(AHEADLIB_VERSION);

	if (IsArch64())
	{
		safeWow64DisableDirectory(redir);
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAheadLibDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAheadLibDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAheadLibDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CAheadLibDlg::OnBnClickedButtonMakefile()
{
	//
	//开始生成文件
	//

	CString str;
	CString source;
	CString source_asm;

	//文件头
	source += g_fileHeader;

	//编译器linker头
	for (auto exFunc : m_exportFunc)
	{

		if (exFunc.isTranFunc) //中转函数
		{
			str.Format(_T("#pragma comment(linker, \"/EXPORT:%s=%s,@%d\")\r\n"),
				exFunc.Name.GetString(), exFunc.TranName.GetString(), exFunc.Ordinal);
		}
		else if (exFunc.isOrd) //序号导出
		{
			if (m_isx64)
			{
				str.Format(_T("#pragma comment(linker, \"/EXPORT:Noname%d=AheadLib_Unnamed%d,@%d,NONAME\")\r\n"),
					exFunc.Ordinal, exFunc.Ordinal, exFunc.Ordinal);
			}
			else
			{
				str.Format(_T("#pragma comment(linker, \"/EXPORT:Noname%d=_AheadLib_Unnamed%d,@%d,NONAME\")\r\n"),
					exFunc.Ordinal, exFunc.Ordinal, exFunc.Ordinal);
			}

		}
		else //名称导出
		{
			if (m_isx64)
			{
				str.Format(_T("#pragma comment(linker, \"/EXPORT:%s=AheadLib_%s,@%d\")\r\n"),
					exFunc.Name.GetString(), exFunc.Name.GetString(), exFunc.Ordinal);
			}
			else
			{
				str.Format(_T("#pragma comment(linker, \"/EXPORT:%s=_AheadLib_%s,@%d\")\r\n"),
					exFunc.Name.GetString(), exFunc.Name.GetString(), exFunc.Ordinal);
			}

		}

		source += str;
	}

	source += _T("\r\n");

	//全局变量定义
	for (auto exFunc : m_exportFunc)
	{
		//
		//第一次先生成 data变量
		//
		if (exFunc.isTranFunc)
		{
			continue;
		}

		if (exFunc.isData)
		{
			if (exFunc.isOrd)
			{
				str.Format(_T("EXTERN_C PVOID AheadLib_Unnamed%d[%d] = { 0 };\r\n"),
					exFunc.Ordinal, exFunc.isDataCount);
			}
			else
			{
				str.Format(_T("EXTERN_C PVOID AheadLib_%s[%d] = { 0 };\r\n"),
					exFunc.Name.GetString(), exFunc.isDataCount);
			}

			source += str;
		}

	}

	source += _T("\r\n");


	if (m_isx64) {
		source += _T("extern \"C\" \n{\r\n");
	}

	for (auto exFunc : m_exportFunc)
	{
		//
		//生成函数指针全局变量
		//
		if (exFunc.isTranFunc)
		{
			continue;
		}

		if (exFunc.isOrd)
		{
			str.Format(_T("PVOID pfnAheadLib_Unnamed%d;\r\n"),
				exFunc.Ordinal);
		}
		else
		{
			str.Format(_T("PVOID pfnAheadLib_%s;\r\n"),
				exFunc.Name.GetString());
		}

		source += str;

	}

	if (m_isx64) {
		source += _T("}\r\n");
	}

	source += _T("\r\n");

	//
	//其他代码
	//
	CString g_init;

	source += g_Free;

	str = g_Load;
	str.Replace(_T("AHEADLIB_XXXXXX.dll"), m_fileName.GetString());
	source += str;

	source += g_GetAddress;
	
	//生成Init函数代码
	g_init = _T("BOOL WINAPI Init()\r\n{\r\n");

	for (auto exFunc : m_exportFunc)
	{
		if (exFunc.isTranFunc)
		{
			continue;
		}

		if (exFunc.isOrd)
		{
			str.Format(_T("\tpfnAheadLib_Unnamed%d = GetAddress(MAKEINTRESOURCEA(%d));\r\n"),
				exFunc.Ordinal, exFunc.Ordinal);
		}
		else
		{
			str.Format(_T("\tpfnAheadLib_%s = GetAddress(\"%s\");\r\n"),
				exFunc.Name.GetString(), exFunc.Name.GetString());
		}

		g_init += str;

		if (exFunc.isData)
		{
			if (exFunc.isOrd)
			{
				str.Format(_T("\tmemcpy(AheadLib_Unnamed%d,pfnAheadLib_Unnamed%d,sizeof(PVOID) * %d);\r\n"),
					exFunc.Ordinal, exFunc.Ordinal, exFunc.isDataCount);
			}
			else
			{
				str.Format(_T("\tmemcpy(AheadLib_%s,pfnAheadLib_%s,sizeof(PVOID) * %d);\r\n"),
					exFunc.Name.GetString(), exFunc.Name.GetString(), exFunc.isDataCount);
			}
			
			g_init += str;
		}

	}

	g_init += _T("\treturn TRUE;\r\n");
	g_init += _T("}\t\n");

	source += g_init;
	source += g_ThreadProc;
	source += g_Dllmain;

	//
	//生成汇编跳转代码
	//
	if (m_isx64)
	{
		source_asm += g_asmFileHeader;

		source_asm += _T(".DATA\r\n");

		for (auto exFunc : m_exportFunc)
		{
			if (exFunc.isTranFunc)
			{
				continue;
			}
			if (exFunc.isData)
			{
				continue;
			}

			if (exFunc.isOrd)
			{
				str.Format(_T("EXTERN pfnAheadLib_Unnamed%d:dq;\r\n"),
					exFunc.Ordinal);
			}
			else
			{
				str.Format(_T("EXTERN pfnAheadLib_%s:dq;\r\n"),
					exFunc.Name.GetString());
			}

			source_asm += str;
		}

		source_asm += _T("\r\n.CODE\r\n");

		for (auto exFunc : m_exportFunc)
		{
			if (exFunc.isTranFunc)
			{
				continue;
			}
			if (exFunc.isData)
			{
				continue;
			}

			if (exFunc.isOrd)
			{
				str.Format(_T(
					"AheadLib_Unnamed%d PROC\r\n"
					"\tjmp pfnAheadLib_Unnamed%d\r\n"
					"AheadLib_Unnamed%d ENDP\r\n\r\n"),
					exFunc.Ordinal, exFunc.Ordinal, exFunc.Ordinal);
			}
			else
			{
				str.Format(_T(
					"AheadLib_%s PROC\r\n"
					"\tjmp pfnAheadLib_%s\r\n"
					"AheadLib_%s ENDP\r\n\r\n"),
					exFunc.Name.GetString(), exFunc.Name.GetString(), exFunc.Name.GetString());
			}

			source_asm += str;
		}

		source_asm += _T("\r\nEND\r\n");

	}
	else
	{
		for (auto exFunc : m_exportFunc)
		{
			if (exFunc.isTranFunc)
			{
				continue;
			}
			if (exFunc.isData)
			{
				continue;
			}

			if (exFunc.isOrd)
			{
				str.Format(_T("EXTERN_C __declspec(naked) void __cdecl AheadLib_Unnamed%d(void)\r\n"
					"{\r\n"
					"\t__asm jmp pfnAheadLib_Unnamed%d;\r\n"
					"}\r\n"),
					exFunc.Ordinal, exFunc.Ordinal);
			}
			else
			{
				str.Format(_T("EXTERN_C __declspec(naked) void __cdecl AheadLib_%s(void)\r\n"
					"{\r\n"
					"\t__asm jmp pfnAheadLib_%s;\r\n"
					"}\r\n"),
					exFunc.Name.GetString(), exFunc.Name.GetString());
			}

			source += str;
			source += _T("\r\n");

		}
	}


	CString outputPath;
	CFile fileOut;
	CStringA ansiSource;

	m_OutputFile.GetWindowText(outputPath);

	if (fileOut.Open(outputPath, CFile::modeCreate | CFile::modeWrite))
	{
		ansiSource = CW2CW(source.GetString());
		fileOut.Write(ansiSource.GetString(), ansiSource.GetLength());
		fileOut.Close();

		AfxMessageBox(_T("Generate code success!"), MB_ICONINFORMATION);
	}

	if (m_isx64)
	{
		CFile fileOutAsm;
		CString outputPathAsm;
		CStringA ansiSourceAsm;

		_tcscpy(outputPathAsm.GetBuffer(outputPath.GetLength() + 16), outputPath.GetString());
		PathRenameExtension(outputPathAsm.GetBuffer(), _T("_jump.asm"));
		outputPathAsm.ReleaseBuffer();

		if (fileOutAsm.Open(outputPathAsm, CFile::modeCreate | CFile::modeWrite))
		{
			ansiSourceAsm = CW2CW(source_asm.GetString());
			fileOutAsm.Write(ansiSourceAsm.GetString(), ansiSourceAsm.GetLength());
			fileOutAsm.Close();
		}
	}
}


void CAheadLibDlg::OnScanFile()
{
	CString str;

	m_fileBuffer = LoadLibraryEx(m_filePath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);

	m_fileName = m_filePath;
	PathStripPath(m_fileName.GetBuffer());
	m_fileName.ReleaseBuffer();

	if (m_fileBuffer == NULL)
	{
		str.Format(_T("Mapping file error! code=%d"), GetLastError());
		AfxMessageBox(str, MB_ICONERROR);
		return;
	}

	PIMAGE_DOS_HEADER dosHead;
	PIMAGE_NT_HEADERS ntHead;
	PIMAGE_NT_HEADERS64 ntHead64;
	PIMAGE_SECTION_HEADER secHead;
	m_isx64 = FALSE;
	BOOL correct = FALSE;

	CString nameString;
	CString fileArch;
	CString timestamp;
	LPCSTR nameStringPtr;
	CString expEdit;

	for (int i = 0; i <= 2; i++)
	{
		dosHead = (PIMAGE_DOS_HEADER)((ULONG_PTR)m_fileBuffer - i);
		if (dosHead->e_magic == IMAGE_DOS_SIGNATURE)
		{
			correct = TRUE;
			break;
		}
	}

	if (!correct)
	{
		AfxMessageBox(_T("Invalid PE File!"), MB_ICONERROR);
		goto _exit;
	}

	if (dosHead->e_magic != IMAGE_DOS_SIGNATURE)
	{
		AfxMessageBox(_T("Invalid DOS Header!"), MB_ICONERROR);
		goto _exit;
	}

	ntHead = ImageNtHeader(dosHead);
	if (ntHead->Signature != IMAGE_NT_SIGNATURE)
	{
		AfxMessageBox(_T("Invalid NT Header!"), MB_ICONERROR);
		goto _exit;
	}

	if (ntHead->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		ntHead->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
	{
		m_isx64 = TRUE;
		ntHead64 = (PIMAGE_NT_HEADERS64)ntHead;
	}

	if (!(ntHead->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		AfxMessageBox(_T("The target is not a dynamic link library!"), MB_ICONERROR);
		goto _exit;
	}

	if (m_isx64)
	{
		if (ntHead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			AfxMessageBox(_T("Export table does not exist!"), MB_ICONERROR);
			goto _exit;
		}
	}
	else
	{
		if (ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
			ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		{
			AfxMessageBox(_T("Export table does not exist!"), MB_ICONERROR);
			goto _exit;
		}
	}

	if (m_isx64)
	{
		secHead = IMAGE_FIRST_SECTION(ntHead64);
	}
	else
	{
		secHead = IMAGE_FIRST_SECTION(ntHead);
	}

	//
	// 获取文件节区表信息
	//

	m_sections.clear();

	if (m_isx64)
	{
		for (WORD i = 0; i < ntHead64->FileHeader.NumberOfSections; i++)
		{
			m_sections.push_back(*secHead);
			secHead++;
		}
	}
	else
	{
		for (WORD i = 0; i < ntHead->FileHeader.NumberOfSections; i++)
		{
			m_sections.push_back(*secHead);
			secHead++;
		}
	}

	//
	//获取导出表信息
	//

	PIMAGE_EXPORT_DIRECTORY exports;
	if (m_isx64)
	{
		exports = (PIMAGE_EXPORT_DIRECTORY)\
			((ULONG)dosHead + ntHead64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}
	else
	{
		exports = (PIMAGE_EXPORT_DIRECTORY)\
			((ULONG)dosHead + ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	nameStringPtr = (LPCSTR)((ULONG_PTR)dosHead + exports->Name);
	if (IsBadReadPtr(nameStringPtr, sizeof(PUCHAR)) == 0)
	{
		nameString = (WCHAR*)CA2W(nameStringPtr);
	}
	else
	{
		nameString = _T("ERROR!");
	}

	m_exportFunc.clear();

	DWORD *pFunc = (DWORD*)(exports->AddressOfFunctions + (ULONG_PTR)dosHead);
	DWORD *nameRVA = (DWORD*)(exports->AddressOfNames + (ULONG_PTR)dosHead);
	int name = 0;

	EXPORT_FUNCTION  *exFunc = new EXPORT_FUNCTION;

 	for (DWORD Index = 0; Index < exports->NumberOfFunctions ; Index++)
	{
		//
		//默认以序号导出
		//

		exFunc->isOrd = TRUE;
		exFunc->Ordinal = exports->Base + Index;
		exFunc->FunctionRVA = pFunc[Index];
		exFunc->NameOrdinal = 0;
		exFunc->NameRVA = 0;
		exFunc->Name = _T("N/A");
		ZeroMemory(&exFunc->secInfo, sizeof(IMAGE_SECTION_HEADER));
		exFunc->isUnkown = FALSE;
		exFunc->isFunc = FALSE;
		exFunc->isTranFunc = FALSE;
		exFunc->isData = FALSE;
		exFunc->isDataCount = 0;

		//
		//过滤无效的RVA
		//

		if (exFunc->FunctionRVA == 0)
		{
			continue;
		}

		WORD *ordName = (WORD*)(exports->AddressOfNameOrdinals + (ULONG_PTR)dosHead);
		for (DWORD i = 0; i < exports->NumberOfNames; i++)
		{
			//
			//查找是否是以名称导出
			//
			if (LOWORD(Index) == *ordName)
			{
				exFunc->isOrd = FALSE;
				exFunc->NameOrdinal = *ordName;
				exFunc->NameRVA = nameRVA[i];
				exFunc->Name = (WCHAR*)CA2W((LPCSTR)((ULONG_PTR)dosHead + exFunc->NameRVA));
				name++;

				break;
			}
			ordName++;
		}

		//
		//查找所在区段,定位导出表函数是否是 函数 或 数据 或 中转导出表
		//

		exFunc->isUnkown = TRUE;
		strcpy((char*)exFunc->secInfo.Name, "ERROR!");
		for (auto sec : m_sections)
		{
			if (exFunc->FunctionRVA >= sec.VirtualAddress &&
				exFunc->FunctionRVA <= (sec.VirtualAddress + sec.Misc.VirtualSize))
			{
				memcpy(&exFunc->secInfo, &sec, sizeof(IMAGE_SECTION_HEADER));

// 				if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
// 					!(sec.Characteristics & IMAGE_SCN_MEM_WRITE))
// 				{
				if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)
				{
					//
					//可运行不可写 代码区段
					//
					exFunc->isFunc = TRUE;
					exFunc->isUnkown = FALSE;
					break;
				}
				if ((sec.Characteristics & IMAGE_SCN_MEM_READ) &&
					!(sec.Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					//
					//可读不可写 .rdata 区段,一般都是中转导出表
					//
					
					char *nameTran = (char*)((ULONG_PTR)dosHead + exFunc->FunctionRVA);
					if (IsBadReadPtr(nameTran,sizeof(void*)) == 0)
					{
						if (strstr(nameTran, ".") != NULL)
						{
							exFunc->isTranFunc = TRUE;
							exFunc->isUnkown = FALSE;
							exFunc->TranName = (WCHAR*)CA2W((LPCSTR)nameTran);
						}
						else
						{
							//
							//无法识别的函数，不知道怎么处理，只有退出
							//
							str.Format(_T(
								"Unknown .rdata section data! continue?\r\n"
								"ord:%d\r\n"
								"func_rva:%08X\r\n"
								"name:%s"),
								exFunc->Ordinal, exFunc->FunctionRVA, exFunc->Name.GetString());

							AfxMessageBox(str, MB_ICONERROR);
							ExitProcess(-1);
							
						}
					}
					else
					{
						str.Format(_T(
							"Try to read .rdata section data exception! continue?\r\n"
							"ord:%d\r\n"
							"func_rva:%08X\r\n"
							"name:%s"),
							exFunc->Ordinal, exFunc->FunctionRVA, exFunc->Name.GetString());

						AfxMessageBox(str, MB_ICONERROR );
						ExitProcess(-1);
						
					}

					break;
				}
				if ((sec.Characteristics & IMAGE_SCN_MEM_READ) &&
					(sec.Characteristics & IMAGE_SCN_MEM_WRITE) &&
					!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
				{
					//
					//可读可写不可运行，数据区段
					//
					exFunc->isData = TRUE;
					exFunc->isUnkown = FALSE;

					//
					//探测数据区段的大小
					//

					if (m_isx64)
					{
						uint64_t *probePtr = (uint64_t*)((ULONG_PTR)dosHead + exFunc->FunctionRVA);
						if (IsBadReadPtr(probePtr,sizeof(void*)) == 0)
						{
							while (TRUE)
							{
								if (*probePtr != NULL)
								{
									exFunc->isDataCount++;
									probePtr++;
								}
								else
								{
									break;
								}
							}
						}
						else
						{
							str.Format(_T(
								"Try to read .data section data exception!\r\n"
								"ord:%d\r\n"
								"func_rva:%08X\r\n"
								"name:%s"),
								exFunc->Ordinal, exFunc->FunctionRVA, exFunc->Name.GetString());

							AfxMessageBox(str, MB_ICONERROR);
							ExitProcess(-1);
						}
					}
					else
					{
						uint32_t *probePtr = (uint32_t*)((ULONG_PTR)dosHead + exFunc->FunctionRVA);
						if (IsBadReadPtr(probePtr, sizeof(void*)) == 0)
						{
							while (TRUE)
							{
								if (*probePtr != NULL)
								{
									exFunc->isDataCount++;
									probePtr++;
								}
								else
								{
									break;
								}
							}
						}
						else
						{
							str.Format(_T(
								"Try to read .data section data exception!\r\n"
								"ord:%d\r\n"
								"func_rva:%08X\r\n"
								"name:%s"),
								exFunc->Ordinal, exFunc->FunctionRVA, exFunc->Name.GetString());

							AfxMessageBox(str, MB_ICONERROR);
							ExitProcess(-1);
						}
					}

					//
					//如果这个导出数据全为空的话，默认给他导出一个指针大小
					//
					if (exFunc->isDataCount == 0)
					{
						exFunc->isDataCount++;
					}

					break;
				}

				AfxMessageBox(_T("Unrecognized export function!"));
				ExitProcess(-1);

				break;
			}
		}

		m_exportFunc.push_back(*exFunc);
	}

	delete exFunc;



	//
	//显示文件信息
	//
	switch (ntHead->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		fileArch = _T("IMAGE_FILE_MACHINE_I386");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		fileArch = _T("IMAGE_FILE_MACHINE_AMD64");
		break;
	case IMAGE_FILE_MACHINE_IA64:
		fileArch = _T("IMAGE_FILE_MACHINE_IA64");
		break;
	default:
		fileArch.Format(_T("Machine->%d"), ntHead->FileHeader.Machine);
		break;
	}

	struct tm* t = localtime((const time_t*)&ntHead->FileHeader.TimeDateStamp);
	if (t != NULL)
	{
		timestamp = _tasctime(t);
	}

	m_NameString.SetWindowText(nameString);
	m_Arch.SetWindowText(fileArch);
	m_Timestamp.SetWindowText(timestamp);

	m_InputFile.SetWindowText(m_filePath);
	str = m_filePath;
	PathRenameExtension((LPWSTR)str.GetString(), _T(".cpp"));
	m_OutputFile.SetWindowText(str);

	for (auto element : m_exportFunc)
	{
		if (element.isFunc)
		{
			str.Format(_T("%04X   %08X   %s | %hs\r\n"),
				element.Ordinal, element.FunctionRVA, element.Name.GetString(), element.secInfo.Name);
		}
		else if (element.isTranFunc)
		{
			str.Format(_T("%04X   %08X   %s | %hs | %s\r\n"),
				element.Ordinal, element.FunctionRVA, element.Name.GetString(), element.secInfo.Name, element.TranName.GetString());
		}
		else if (element.isData)
		{
			str.Format(_T("%04X   %08X   %s | %hs | DATA<%d>\r\n"),
				element.Ordinal, element.FunctionRVA, element.Name.GetString(), element.secInfo.Name, element.isDataCount);
		}
		else if(element.isUnkown)
		{
			str.Format(_T("%04X   %08X   %s | %hs | ???\r\n"),
				element.Ordinal, element.FunctionRVA, element.Name.GetString(), element.secInfo.Name);
		}
		else
		{
			//
			//理论不会走到这里来
			//
			AfxMessageBox(_T("GG!"));
			ExitProcess(-2);
		}

		expEdit += str;
	}

	m_show.SetWindowText(expEdit);

_exit:
	
	FreeLibrary(m_fileBuffer);
}


void CAheadLibDlg::OnGenerateCode()
{

}

void CAheadLibDlg::OnBnClickedButtonExit()
{
	CAheadLibDlg::OnOK();
}


void CAheadLibDlg::OnDropFiles(HDROP hDropInfo)
{
	TCHAR szFilePath[MAX_PATH];

	DragQueryFile(hDropInfo, 0, szFilePath, sizeof(szFilePath));
	DragFinish(hDropInfo);

	m_filePath = szFilePath;

	OnScanFile();

	CDialog::OnDropFiles(hDropInfo);
}


void CAheadLibDlg::OnBnClickedButtonChosefile()
{
	TCHAR szFilter[] = _T("Dynamic Link Library(*.dll)|*.dll|All Files(*.*)|*.*||");
	CFileDialog fileDlg(TRUE, _T("dll"), NULL, 0, szFilter, this);
	CString strFilePath;

	if (IDOK == fileDlg.DoModal())
	{
		strFilePath = fileDlg.GetPathName();
		m_InputFile.SetWindowText(strFilePath);

		m_filePath = strFilePath;
		OnScanFile();
	}
}


void CAheadLibDlg::OnBnClickedButtonSavefile()
{
	TCHAR szFilter[] = _T("C++ Source(*.cpp)|*.cpp|All Files(*.*)|*.*||");
	CFileDialog fileDlg(FALSE, _T("cpp"), _T("mydll"), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, szFilter, this);
	CString strFilePath;

	if (IDOK == fileDlg.DoModal())
	{
		strFilePath = fileDlg.GetPathName();
		m_OutputFile.SetWindowText(strFilePath);
	}

}
