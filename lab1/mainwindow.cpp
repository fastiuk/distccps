#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sha.h"
#include <cstring>

using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    uint8_t sha[SHASUM_SIZE];
    char sha_str[SHASUM_SIZE * 2 + 1];
    QString text = ui->textEdit->toPlainText();

    if (sha1_calculate(text.toStdString().c_str(), text.toStdString().length(),
                       sha, sizeof(sha)) == 0) {
        for (uint i = 0; i < SHASUM_SIZE; ++i) {
            sprintf(&sha_str[i * 2], "%02x", sha[i]);
        }
        ui->textEdit_2->setText(QString::fromStdString(string(sha_str)));
    } else {
        ui->textEdit_2->setText(QString::fromStdString(string("SHA ERROR")));
    }
}
