#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_gen_keys_clicked();

    void on_pushButton_gen_sess_key_clicked();

    void on_pushButton_encr_clicked();

    void on_pushButton_decr_clicked();

    void on_pushButton_validate_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
