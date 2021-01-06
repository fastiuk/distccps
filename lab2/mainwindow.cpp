#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <cstring>

extern "C" {
#include "dsa.h"
}

using namespace std;

static dsa_param_t param;
static dsa_keypair_t keypair;
static dsa_signature_t signature;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    if (dsa_self_test()) {
        printf("DSA self test failed\n");
    } else {
        printf("DSA self test successful\n");
    }

    dsa_init();
}

MainWindow::~MainWindow()
{
    dsa_destroy();
    delete ui;
}

void MainWindow::on_pushButton_generate_params_clicked()
{
    dsa_generate_param(&param);
    dsa_generate_keypair(&param, &keypair);

    ui->textEdit_param_p->setText(QString::fromStdString(string(param.p)));
    ui->textEdit_param_q->setText(QString::fromStdString(string(param.q)));
    ui->textEdit_param_g->setText(QString::fromStdString(string(param.g)));
    ui->textEdit_priv_key->setText(QString::fromStdString(string(keypair.x)));
    ui->textEdit_publ_key->setText(QString::fromStdString(string(keypair.y)));

    ui->textEdit_param_r->setText(QString::fromStdString(string("")));
    ui->textEdit_signature->setText(QString::fromStdString(string("")));
    ui->label_validation_result->setText(QString::fromStdString(string("")));
}

void MainWindow::on_pushButton_sign_clicked()
{
    dsa_sign(&param, &keypair,
             ui->textEdit_msg->toPlainText().toStdString().c_str(),
             ui->textEdit_msg->toPlainText().toStdString().length(),
             &signature);

    ui->textEdit_param_r->setText(QString::fromStdString(string(signature.r)));
    ui->textEdit_signature->setText(QString::fromStdString(string(signature.s)));

    ui->label_validation_result->setText(QString::fromStdString(string("")));
}

void MainWindow::on_pushButton_validate_clicked()
{
    int res;

    // For testing purposes
    strncpy(param.p, ui->textEdit_param_p->toPlainText().toStdString().c_str(),
            sizeof(param.p));
    strncpy(param.q, ui->textEdit_param_q->toPlainText().toStdString().c_str(),
            sizeof(param.q));
    strncpy(param.g, ui->textEdit_param_g->toPlainText().toStdString().c_str(),
            sizeof(param.g));
    strncpy(keypair.x,
            ui->textEdit_priv_key->toPlainText().toStdString().c_str(),
            sizeof(keypair.x));
    strncpy(keypair.y,
            ui->textEdit_publ_key->toPlainText().toStdString().c_str(),
            sizeof(keypair.y));
    strncpy(signature.r,
            ui->textEdit_param_r->toPlainText().toStdString().c_str(),
            sizeof(signature.r));
    strncpy(signature.s,
            ui->textEdit_signature->toPlainText().toStdString().c_str(),
            sizeof(signature.s));

    res = dsa_validate(&param, &keypair,
                       ui->textEdit_msg->toPlainText().toStdString().c_str(),
                       ui->textEdit_msg->toPlainText().toStdString().length(),
                       &signature);
    if (res) {
        ui->label_validation_result->setText(
                       QString::fromStdString(string("DSA signature invalid")));
    } else {
        ui->label_validation_result->setText(
                      QString::fromStdString(string("DSA signature is valid")));
    }
}
