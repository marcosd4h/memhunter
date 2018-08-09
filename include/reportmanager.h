#pragma once

#include "common.h"

class ReportManager
{
public:
	static ReportManager& GetInstance()
	{
		static ReportManager instance;
		return instance;
	}

	bool GetReportElement(const DWORD pid, const CustomTypes::HunterID &hunterID, HunterCommon::SuspiciousProcessDataPtr &element);

	void Clear();

	bool PopulateCommonFields(const DWORD pid,
		const DWORD tid,
		const HunterCommon::ProcessDataPtr &processData,
		HunterCommon::SuspiciousProcessDataPtr &reportElement);

	bool ReportFindings(const CustomTypes::ReportVerbosity &verbosity,
		const CustomTypes::ReportOutput &output);

private:
	ReportManager() {};

	//Print findings
	bool PrintFindingsOnConsole(const CustomTypes::ReportVerbosity &mode);
	bool PrintFindingsOnEventLog(const CustomTypes::ReportVerbosity &mode);
	std::wstring GetCommonReportData(
		const HunterCommon::SuspiciousProcessDataPtr &suspiciousProcessData,
		const CustomTypes::ReportVerbosity &mode);

	ReportManager(const ReportManager&) = delete;
	ReportManager& operator = (const ReportManager&) = delete;

	HunterCommon::SuspiciousProcessess m_container;
	std::mutex m_lock;
};
