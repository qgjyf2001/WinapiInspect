#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include <thread>
#include <mutex>
#include <queue>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    void printDebugMessage(std::string s);
    ~MainWindow();
    HANDLE hPipe;

private slots:
    void on_timeout();

    void on_refreshButton_clicked();

    void on_browseButton_clicked();

    void on_injectButton_clicked();

    void on_pushButton_clicked();

    void on_injectNewProcessButton_clicked();

    void on_hookSelectedRatioButton_clicked();

    void on_hookAllRadioButton_clicked();

    void on_removeFunctionButton_clicked();

    void on_addFunctionButton_clicked();

    void on_removeDllButton_clicked();

    void on_addDllButton_clicked();

private:
    void refreshProcessList();
    bool dllInject(DWORD pid);
    void saveHookFunctionList();
    bool hookAll = false;
    std::string dllPath;
    Ui::MainWindow *ui;
    QTimer *timer;
    QThread* pipeThread;
    std::mutex mutex;
    std::queue<std::string> debugMsgQueue;

};
#endif // MAINWINDOW_H
