#include "common.h"

bool HuntingDB::InitializeDB(const std::wstring &dbname)
{
	bool ret = false;

	try
	{
		//creating full db file path
		std::wstring appdataPath;
		if (GeneralHelpers::GetUserProfileDirectory(appdataPath))
		{
			m_DBFile.assign(appdataPath + L"\\" + dbname);
		}
		else
		{
			m_DBFile.assign(dbname);
		}

		//deleting previous instances
		if (m_ptrHuntingDB != nullptr)
		{
			delete m_ptrHuntingDB;
		}

		//deleting previous db files
		if (GeneralHelpers::IsValidFile(m_DBFile))
		{
			DeleteFile(m_DBFile.c_str());
		}

		//Creating new DB instance
		std::string sqliteDBName(m_DBFile.begin(), m_DBFile.end());
		m_ptrHuntingDB = new sqlite::database(sqliteDBName.c_str());

		// executes the query and creates the "RunningProcesses" table
		*m_ptrHuntingDB <<
			"create table if not exists RunningProcesses ("
			"   _id integer primary key autoincrement not null,"
			"   UniqueProcessKey integer,"
			"   ProcessId integer,"
			"   ParentId integer,"
			"   SessionId integer,"
			"   ExitStatus integer,"
			"   ImageFileName string,"
			"   CommandLine string,"
			"   ProcessEnded integer,"
			"   StartTime integer,"
			"   EndTime integer"
			");";

		// executes the query and creates the "RemoteThreads" table
		*m_ptrHuntingDB <<
			"create table if not exists RemoteThreads ("
			"   _id integer primary key autoincrement not null,"
			"   ProcessId integer,"
			"   TThreadId integer,"
			"   CallerProcessId integer,"
			"   CallerTThreadId integer,"
			"   BasePriority integer,"
			"   PagePriority integer,"
			"   IoPriority integer,"
			"   ThreadFlags integer,"
			"   Win32StartAddr integer,"
			"   TebBase integer,"
			"   ThreadEnded integer,"
			"   StartTime integer,"
			"   EndTime integer"
			");";

		// executes the query and creates the "RemoteAllocs" table
		*m_ptrHuntingDB <<
			"create table if not exists RemoteAllocs ("
			"   _id integer primary key autoincrement not null,"
			"   ProcessId integer,"
			"   CallerProcessId integer,"
			"   CallerTThreadId integer,"
			"   BaseAddress integer,"
			"   Flags integer,"
			"   AllocationTimestamp integer"
			");";

		int runningProcessesCount = 0;
		int remoteThreadsCount = 0;
		int remoteAllocCount = 0;

		*m_ptrHuntingDB << "select count(*) from RunningProcesses" >> runningProcessesCount;
		*m_ptrHuntingDB << "select count(*) from RemoteThreads" >> remoteThreadsCount;
		*m_ptrHuntingDB << "select count(*) from RemoteAllocs" >> remoteAllocCount;

		if ((runningProcessesCount == 0) && (remoteThreadsCount == 0) && (remoteAllocCount == 0))
		{
			ret = true;
		}
	}
	catch (...)
	{
		TraceHelpers::TraceConsoleDown("There was a problem initializing the hunting DB");
	}

	return ret;
}

bool HuntingDB::IsInitialized()
{
	bool ret = false;

	if (m_ptrHuntingDB != nullptr)
	{
		ret = true;
	}

	return ret;
}

bool HuntingDB::AddUpdateRemoteProcess(const HunterCommon::ETWRemoteProcessData &data)
{
	bool ret = false;

	try
	{
		if (IsInitialized())
		{
			int IsProcessPresent = 0;
			*m_ptrHuntingDB << "select count(*) from RunningProcesses where UniqueProcessKey = ?"
				<< data.UniqueProcessKey
				>> IsProcessPresent;

			if (IsProcessPresent != 0)
			{
				*m_ptrHuntingDB << "update RunningProcesses SET ExitStatus = ?, ProcessEnded = ?, EndTime = ? where UniqueProcessKey = ?"
					<< data.ExitStatus
					<< 0x1
					<< data.EndTime
					<< data.UniqueProcessKey;
			}
			else
			{
				*m_ptrHuntingDB << "insert into RunningProcesses (UniqueProcessKey,ProcessId,ParentId,SessionId,ExitStatus,ImageFileName,CommandLine,ProcessEnded,StartTime,EndTime) values (?,?,?,?,?,?,?,?,?,?);"
					<< data.UniqueProcessKey
					<< data.ProcessId
					<< data.ParentId
					<< data.SessionId
					<< data.ExitStatus
					<< data.ImageFileName
					<< data.CommandLine
					<< data.ProcessEnded
					<< data.StartTime
					<< data.EndTime;
			}

			ret = true;
		}
	}
	catch (sqlite::sqlite_exception e)
	{
		TraceHelpers::TraceConsoleDown("There was a problem AddUpdateRemoteProcess entry to the hunting DB");
		TraceHelpers::TraceConsoleDown("Unexpected error: %s", e.what());
	}

	return ret;
}

bool HuntingDB::AddUpdateRemoteThread(const HunterCommon::ETWRemoteThreadData &data)
{
	bool ret = false;

	try
	{
		if (IsInitialized())
		{
			*m_ptrHuntingDB << "insert into RemoteThreads (ProcessId,TThreadId,CallerProcessId,CallerTThreadId,BasePriority,PagePriority,IoPriority,ThreadFlags,Win32StartAddr,TebBase,ThreadEnded,StartTime,EndTime) values (?,?,?,?,?,?,?,?,?,?,?,?,?);"
				<< data.ProcessId
				<< data.TThreadId
				<< data.CallerProcessId
				<< data.CallerTThreadId
				<< data.BasePriority
				<< data.PagePriority
				<< data.IoPriority
				<< data.ThreadFlags
				<< data.Win32StartAddr
				<< data.TebBase
				<< data.ThreadEnded
				<< data.StartTime
				<< data.EndTime;

			ret = true;
		}
	}
	catch (...)
	{
		TraceHelpers::TraceConsoleDown("There was a problem AddUpdateRemoteThread entry to the hunting DB");
	}

	return ret;
}

bool HuntingDB::AddUpdateRemoteAlloc(const HunterCommon::ETWRemoteAllocData &data)
{
	bool ret = false;

	try
	{
		std::wstring processName;
		if ((IsInitialized()) && 
			(ConfigManager::GetInstance().IsProcessExcluded(data.ProcessId)))
		{
			//Deciding if we should skip this record or not
			*m_ptrHuntingDB << "insert into RemoteAllocs (ProcessId,CallerProcessId,CallerTThreadId,BaseAddress,Flags,AllocationTimestamp) values (?,?,?,?,?,?);"
				<< data.ProcessId
				<< data.CallerProcessId
				<< data.CallerTThreadId
				<< data.BaseAddress
				<< data.Flags
				<< data.AllocationTimestamp;

			ret = true;
		}
	}
	catch (...)
	{
		TraceHelpers::TraceConsoleDown("There was a problem AddUpdateRemoteAlloc entry to the hunting DB");
	}

	return ret;
}
