#include "mainwindow.h"
#include "ui_mainwindow.h"

extern "C" {
#include "dsa.h"
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    dsa_test();
}

MainWindow::~MainWindow()
{
    delete ui;
}

