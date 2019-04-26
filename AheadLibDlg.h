
// AheadLibDlg.h: 头文件
//

#pragma once

typedef struct _EXPORT_FUNCTION
{
	BOOL isOrd;
	DWORD Ordinal;
	DWORD FunctionRVA;
	DWORD NameOrdinal;
	DWORD NameRVA;
	CString Name;

	IMAGE_SECTION_HEADER secInfo; //区段信息

	BOOL isUnkown;
	BOOL isFunc; //是否是函数
	BOOL isTranFunc; //是否是中转导出表
	BOOL isData; //是否是数据
	ULONG isDataCount; //导出数据大小，每一个指针当一个计数 
	CString TranName; //中转导出表名称

}EXPORT_FUNCTION, *PEXPORT_FUNCTION;

// CAheadLibDlg 对话框
class CAheadLibDlg : public CDialog
{
// 构造
public:
	CAheadLibDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_AHEADLIB_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_isx64;
	CString m_fileName;
	CString m_filePath;
 	HMODULE m_fileBuffer;
	std::vector<IMAGE_SECTION_HEADER> m_sections;
	std::vector<EXPORT_FUNCTION> m_exportFunc;

	CEdit m_show;
	CStatic m_NameString;
	CStatic m_Arch;
	CStatic m_Timestamp;
	CEdit m_InputFile;
	CEdit m_OutputFile;

	void OnScanFile();
	void OnGenerateCode();

	afx_msg void OnBnClickedButtonExit();
	afx_msg void OnBnClickedButtonMakefile();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButtonChosefile();
	afx_msg void OnBnClickedButtonSavefile();
};
