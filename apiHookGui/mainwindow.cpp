#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "windows.h"
#include "psapi.h"
#include "QTimer"
#include "QDebug"
#include <QFileDialog>
#include "Shlwapi.h"
#include <QThread>
#include "hook_factory.h"

static constexpr auto pipeName = "\\\\.\\pipe\\hookCommutePipe";
static constexpr auto BuffSize = 1024;

class PipeThread: public QThread {
public:
    PipeThread(MainWindow* mainWindow) : mainWindow(mainWindow) {

    }
private:
    MainWindow* mainWindow;
protected:
    void run() {
        mainWindow->hPipe = CreateNamedPipeA(pipeName,
                                 PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                 PIPE_TYPE_BYTE,
                                 1,
                                 BuffSize, BuffSize,
                                 0, NULL
                                 );
        if (mainWindow->hPipe == INVALID_HANDLE_VALUE) {
            mainWindow->printDebugMessage("server create Pipe error: " + GetLastError());
        } else {
            mainWindow->printDebugMessage("create pipe success");
        }
        while (true) {
            int flag = ConnectNamedPipe(mainWindow->hPipe, NULL);
            if (flag != 0) {
                char buff[BuffSize] = {0};
                DWORD readLength = 0;
                flag = ReadFile(mainWindow->hPipe, buff, BuffSize, &readLength, NULL);
                if (flag != 0 && readLength > 0) {
                    mainWindow->printDebugMessage(std::string(buff, readLength));
                }
            }
            DisconnectNamedPipe(mainWindow->hPipe);
        }
    }
};

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    refreshProcessList();
    dllPath = (QCoreApplication::applicationDirPath() + "/../libs/apiHook.dll").toStdString();
    ui->dllPath->setText(QString::fromStdString(dllPath));
    pipeThread = new PipeThread(this);
    pipeThread->start();
    for (size_t i = 0; i < std::tuple_size_v<decltype(hookFunctionDefs)>; i++) {
        std::string enum_name = std::string(magic_enum::enum_name(static_cast<hookFunctionEnum>(i)));
        ui->selectFunctionList->addItem(QString::fromStdString(enum_name));
    }
    ui->removedWinapiList->setAutoCompletion(true);
    timer = new QTimer();
    timer->setInterval(50);
    connect(timer, &QTimer::timeout, this, &MainWindow::on_timeout);
    timer->start();
}

MainWindow::~MainWindow()
{
    pipeThread->terminate();
    CloseHandle(hPipe);
    delete ui;
}

void MainWindow::refreshProcessList(){
    ui->processList->clear();
    DWORD processIds[65535] = {0};
    DWORD cbNeeded = 0;
    EnumProcesses(processIds, sizeof(processIds), &cbNeeded);
    auto cProcess = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < cProcess; i++) {
        char pathName[1024] = {0};
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                          PROCESS_VM_READ,
                                      FALSE, processIds[i] );
        if (hProcess!=nullptr) {
            {

                GetModuleFileNameExA ( hProcess, nullptr, pathName,
                                  sizeof(pathName) );
                auto processName = PathFindFileNameA(pathName);
                ui->processList->addItem(QString::number(processIds[i]) + " " + QString::fromLocal8Bit(processName));
            }
        }
        CloseHandle(hProcess);
    }
}

void MainWindow::saveHookDllList() {
    char path[256] = {0};
    GetTempPathA(sizeof(path), path);
    strcat(path, "hook_dll_list.txt");
    auto file = fopen(path,"w");
    if (ui->hookAllRadioButton->isChecked()) {
        auto functionSize = ui->selectDllList->count();
        for (int i = 0; i < functionSize; i++) {
            QString functionName = ui->selectDllList->item(i)->text();
            fprintf(file, "%s\n", functionName.toLocal8Bit().data());
        }
    }
    fclose(file);
}

void MainWindow::saveHookFunctionList() {
    char path[256] = {0};
    GetTempPathA(sizeof(path), path);
    strcat(path, "hook_function_list.txt");
    auto file = fopen(path,"w");
    if (ui->hookSelectedRatioButton->isChecked()) {
        auto functionSize = ui->selectFunctionList->count();
        for (int i = 0; i < functionSize; i++) {
            QString functionName = ui->selectFunctionList->item(i)->text();
            fprintf(file, "%s\n", functionName.toLocal8Bit().data());
        }
    }
    fclose(file);
}

bool MainWindow::dllInject(DWORD pid) {
    saveHookFunctionList();
    saveHookDllList();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    LPVOID pRemoteAddress = VirtualAllocEx(
        hProcess,
        NULL,
        dllPath.size(),
        MEM_COMMIT,
        PAGE_READWRITE
        );
    DWORD dwWriteSize = 0;
    BOOL bRet = WriteProcessMemory(hProcess, pRemoteAddress, dllPath.data(), dllPath.size(), NULL);
    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (!hModule)
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    LPTHREAD_START_ROUTINE dwLoadAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
    if (!dwLoadAddr)
    {
        CloseHandle(hProcess);
        CloseHandle(hModule);
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)dwLoadAddr,
        pRemoteAddress,
        NULL,
        NULL
        );
    return TRUE;
}

void MainWindow::on_refreshButton_clicked()
{
    refreshProcessList();
}


void MainWindow::on_browseButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(nullptr, "choose hook dll", QString::fromStdString(dllPath));
    if (!filePath.size() == 0) {
        dllPath = filePath.toStdString();
    }
    ui->dllPath->setText(QString::fromStdString(dllPath));
}

void MainWindow::printDebugMessage(std::string s) {
    std::lock_guard<std::mutex> lock_guard(mutex);
    debugMsgQueue.push(s);
}

void MainWindow::on_timeout() {
    std::lock_guard<std::mutex> lock_guard(mutex);
    while (!debugMsgQueue.empty()) {
        auto s = debugMsgQueue.front();
        ui->debugWindow->append(QString::fromLocal8Bit(s.data()));
        ui->debugWindow->moveCursor(QTextCursor::End);
        debugMsgQueue.pop();
    }
}

void MainWindow::on_injectButton_clicked()
{
    auto pid = ui->processList->currentText().split(" ")[0].toInt();
    const char* status = dllInject(pid) ? " success" : " failed";
    printDebugMessage("pid " + std::to_string(pid) + " inject " + dllPath + status);
}


void MainWindow::on_pushButton_clicked()
{
    MessageBoxA(nullptr, "This is a test", "MessageBox Test", 0);
}


void MainWindow::on_injectNewProcessButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(nullptr, "select a process to start",
                                                    QCoreApplication::applicationDirPath(), "Executable File(*.exe)");
    if (filePath.size() == 0) {
        return;
    }
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, filePath.toLocal8Bit().data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    dllInject(pi.dwProcessId);
    ResumeThread(pi.hThread);
}


void MainWindow::on_hookSelectedRatioButton_clicked()
{
    hookAll = false;
}


void MainWindow::on_hookAllRadioButton_clicked()
{
    hookAll = true;
}


void MainWindow::on_removeFunctionButton_clicked()
{
    auto item = ui->selectFunctionList->currentItem();
    if (item != nullptr) {
        ui->removedWinapiList->addItem(item->text());
        ui->selectFunctionList->removeItemWidget(item);
        delete item;
    }
}


void MainWindow::on_addFunctionButton_clicked()
{
    auto item = ui->removedWinapiList->currentText();
    if (item.size() != 0) {
        ui->selectFunctionList->addItem(item);
        ui->removedWinapiList->removeItem(ui->removedWinapiList->currentIndex());
    }
}


void MainWindow::on_removeDllButton_clicked()
{
    auto item = ui->selectDllList->currentItem();
    if (item != nullptr) {
        ui->selectDllList->removeItemWidget(item);
        delete item;
    }
}


void MainWindow::on_addDllButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(nullptr, "select a dll to hook",
                                                    "C:/windows/system32", "Dynamic Link Library(*.dll)");
    if (filePath != nullptr) {
        ui->selectDllList->addItem(filePath);
    }
}


void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    ui->debugWindow->moveCursor(QTextCursor::End);
    if (arg1.size() != 0) {
        if(ui->debugWindow->find(arg1,QTextDocument::FindBackward)) {
            QPalette palette = ui->debugWindow->palette();
            palette.setColor(QPalette::Highlight,palette.color(QPalette::Active,QPalette::Highlight));
            ui->debugWindow->setPalette(palette);
        }
    } else {
        auto cursor = ui->debugWindow->textCursor();
        cursor.clearSelection();
        ui->debugWindow->setTextCursor(cursor);
    }
}

