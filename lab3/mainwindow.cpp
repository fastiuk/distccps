#include "mainwindow.h"
#include "ui_mainwindow.h"

extern "C" {
#include "cast128.h"
}

using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // CAST self test
    if (cast128_self_test()) {
        printf("CAST128 self test failed\n");
    } else {
        printf("CAST128 self test successful\n");
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_textEdit_key_textChanged()
{
    // Crop key to 16 bytes
    if (ui->textEdit_key->toPlainText().length() > 16) {
        ui->textEdit_key->setPlainText(ui->textEdit_key->toPlainText().left(
                                ui->textEdit_key->toPlainText().length() - 1));
        ui->textEdit_key->moveCursor(QTextCursor::End);
    }
}

void MainWindow::on_pushButton_encrypt_clicked()
{
    cast_key_t key;
    uint8_t rawkey[CAST_KEY_16] = {0};
    size_t keylen;
    char *text;
    char *hex;
    size_t blocks;

    keylen = ui->textEdit_key->toPlainText().toStdString().length();
    if (keylen > CAST_KEY_16) {
        keylen = CAST_KEY_16;
    }

    // Copy rawkey
    memcpy(rawkey, ui->textEdit_key->toPlainText().toStdString().c_str(),
           keylen);
    cast128_set_key(&key, rawkey, CAST_KEY_16);

    // Calculating blocks count
    blocks = ui->textEdit_plain_text->toPlainText().toStdString().length() / 8;
    blocks +=
            ui->textEdit_plain_text->toPlainText().toStdString().length() % 8 ?
            1 : 0;

    // Alloc memory for text and hex string
    text = (char *)calloc(blocks * 8, 1);
    hex = (char *)calloc(blocks * 8 * 2, 1);

    memcpy(text, ui->textEdit_plain_text->toPlainText().toStdString().c_str(),
           ui->textEdit_plain_text->toPlainText().toStdString().length());

    for (size_t i = 0; i < blocks; ++i) {
        cast128_crypt(&key, (uint8_t *)&text[i * 8], CAST_ENCRYPT);
    }

    // Convert plain text to hex string
    for (size_t i = 0; i < blocks * 8; ++i) {
        sprintf(&hex[i * 2], "%02hhx", text[i]);
    }

    ui->textEdit_encrypted_text->setText(QString::fromStdString(string(hex)));

    free(text);
    free(hex);
}

void MainWindow::on_pushButton_decrypt_clicked()
{
    cast_key_t key;
    uint8_t rawkey[CAST_KEY_16] = {0};
    size_t keylen;
    char *text;
    char *hex;
    size_t blocks;

    keylen = ui->textEdit_key->toPlainText().toStdString().length();
    if (keylen > CAST_KEY_16) {
        keylen = CAST_KEY_16;
    }

    // Copy rawkey
    memcpy(rawkey, ui->textEdit_key->toPlainText().toStdString().c_str(),
           keylen);
    cast128_set_key(&key, rawkey, CAST_KEY_16);

    // Calculating blocks count
    blocks =
        ui->textEdit_encrypted_text->toPlainText().toStdString().length() / 2 /
        8;

    // Alloc memory for text and hex string
    text = (char *)calloc(blocks * 8 + 1, 1);
    hex = (char *)calloc(blocks * 8 * 2, 1);

    memcpy(hex,
           ui->textEdit_encrypted_text->toPlainText().toStdString().c_str(),
           blocks * 8 * 2);

    // Convert hex string to plain text
    for (size_t i = 0; i < blocks * 8; ++i) {
        sscanf(&hex[i * 2], "%02hhx", &text[i]);
    }

    for (size_t i = 0; i < blocks; ++i) {
        cast128_crypt(&key, (uint8_t *)&text[i * 8], CAST_DECRYPT);
    }

    ui->textEdit_plain_text->setText(QString::fromStdString(string(text)));

    free(text);
    free(hex);
}
