#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include <thread>
#include <mutex>

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
    void on_refreshButton_clicked();

    void on_browseButton_clicked();

    void on_injectButton_clicked();

    void on_pushButton_clicked();

    void on_injectNewProcessButton_clicked();

private:
    void refreshProcessList();
    bool dllInject(DWORD pid);
    std::string dllPath;
    Ui::MainWindow *ui;
    QThread* pipeThread;
    std::mutex mutex;
};
#endif // MAINWINDOW_H
