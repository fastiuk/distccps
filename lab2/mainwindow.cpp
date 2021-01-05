#include "mainwindow.h"
#include "ui_mainwindow.h"

extern "C" {
#include "dsa.h"
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    dsa_param_t par;
    dsa_keypair_t kp;
    dsa_signature_t sign;

    ui->setupUi(this);

    if (dsa_self_test()) {
        printf("DSA self test failed\n");
    } else {
        printf("DSA self test successful\n");
    }

    dsa_init();
    dsa_generate_param(&par);
    dsa_generate_keypair(&par, &kp);
    dsa_sign(&par, &kp, "Hello", 5, &sign);
    if (dsa_validate(&par, &kp, "Hello", 5, &sign)) {
        printf("DSA signature invalid\n");
    } else {
        printf("DSA signature is valid\n");
    }

    dsa_destroy();
}

MainWindow::~MainWindow()
{
    delete ui;
}

