#include "mainwindow.h"
#include "ui_mainwindow.h"

extern "C" {
#include <cast128.h>
#include <sha.h>
}

#define KEY_SIZE    16
#define SIGN_SIZE   20

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

static void print_bytes(char *header, uint8_t *data, size_t size)
{
    printf("%s: ", header);
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx", data[i]);
    }
    printf("\n");
}

static int text_to_data(const char *text, size_t tsize, uint8_t *data, size_t dsize)
{
    if (tsize / 2 > dsize) {
        return -1;
    }

    for (size_t i = 0; i < dsize; ++i) {
        sscanf(&text[i * 2], "%02hhx", &data[i]);
    }

    return 0;
}

static int data_to_text(uint8_t *data, size_t dsize, char *text, size_t tsize)
{
    if (dsize * 2 >= tsize) {
        return -1;
    }

    memset(text, 0, tsize);
    for (size_t i = 0; i < dsize; ++i) {
        sprintf(&text[i * 2], "%02hhx", data[i]);
    }

    return 0;
}

static int cesar_asym_encrypt(uint8_t *key, size_t ksize, uint8_t *data,
                               size_t dsize)
{
    uint8_t x = 0;

    for (size_t i = 0; i < ksize; ++i) {
        x += key[i];
    }

    for (size_t i = 0; i < dsize; ++i) {
        data[i] += x;
    }

    return 0;
}

static int cesar_asym_decrypt(uint8_t *key, size_t ksize, uint8_t *data,
                               size_t dsize)
{
    uint8_t x = 0;

    for (size_t i = 0; i < ksize; ++i) {
        x += key[i];
    }

    for (size_t i = 0; i < dsize; ++i) {
        data[i] -= x;
    }

    return 0;
}

static int cesar_shuffle_key(uint8_t *key, size_t ksize)
{
    uint8_t x = 0;

    for (size_t i = 0; i < ksize / 2; ++i) {
        size_t j = ksize - i - 1;
        key[i] = key[i] ^ key[j];
        key[j] = key[i] ^ key[j];
        key[i] = key[i] ^ key[j];
    }

    return 0;
}

void MainWindow::on_pushButton_gen_keys_clicked()
{
    char text[KEY_SIZE * 2 + 1];
    uint8_t key1[KEY_SIZE];
    uint8_t key2[KEY_SIZE];

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key1[i] = rand() % 256;
        key2[i] = rand() % 256;
    }

    data_to_text(key1, sizeof(key1), text, sizeof(text));
    ui->textEdit_u1_pr_key->setText((QString::fromStdString(string(text))));

    cesar_shuffle_key(key1, sizeof(key1));
    data_to_text(key1, sizeof(key1), text, sizeof(text));
    ui->textEdit_u1_pub_key->setText((QString::fromStdString(string(text))));

    data_to_text(key2, sizeof(key2), text, sizeof(text));
    ui->textEdit_u2_pr_key->setText((QString::fromStdString(string(text))));

    cesar_shuffle_key(key2, sizeof(key2));
    data_to_text(key2, sizeof(key2), text, sizeof(text));
    ui->textEdit_u2_pub_key->setText((QString::fromStdString(string(text))));
}

void MainWindow::on_pushButton_gen_sess_key_clicked()
{
    char text[KEY_SIZE * 2 + 1];
    uint8_t key_session[KEY_SIZE];
    uint8_t hex_u2_pub[KEY_SIZE];

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key_session[i] = rand() % 256;
    }

    // Encrypt session
    text_to_data(ui->textEdit_u2_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pub_key->toPlainText().toStdString().length(),
                 hex_u2_pub, sizeof(hex_u2_pub));
    cesar_asym_encrypt(hex_u2_pub, sizeof(hex_u2_pub), key_session,
                        sizeof(key_session));

    data_to_text(key_session, sizeof(key_session), text, sizeof(text));
    ui->textEdit_sess_key->setText((QString::fromStdString(string(text))));
}

void MainWindow::on_pushButton_encr_clicked()
{
    cast_key_t cast_key;
    char key_text[SIGN_SIZE * 2 + 1];
    uint8_t hex_u1_pr[KEY_SIZE];
    uint8_t hex_u2_pub[KEY_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t text_size;
    uint8_t signature[SIGN_SIZE];
    uint8_t key_session[KEY_SIZE];

    // Get message
    msg_size = ui->textEdit_u1_msg->toPlainText().toStdString().length();
    text_size = (msg_size + 8) * 2 + 1;
    msg = (char *)calloc(msg_size + 8, 1);
    text = (char *)calloc(text_size, 1);
    memcpy(msg, ui->textEdit_u1_msg->toPlainText().toStdString().c_str(),
           msg_size);

    sha1_calculate(msg, msg_size, signature, sizeof(signature));

    // Encrypt signature
    text_to_data(ui->textEdit_u1_pr_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u1_pr_key->toPlainText().toStdString().length(),
                 hex_u1_pr, sizeof(hex_u1_pr));
    cesar_asym_encrypt(hex_u1_pr, sizeof(hex_u1_pr), signature,
                       sizeof(signature));
    data_to_text(signature, sizeof(signature), key_text, sizeof(key_text));
    ui->textEdit_dig_sign->setText((QString::fromStdString(string(key_text))));

    // Decrypt session
    text_to_data(ui->textEdit_sess_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_sess_key->toPlainText().toStdString().length(),
                 key_session, sizeof(key_session));
    text_to_data(ui->textEdit_u2_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pub_key->toPlainText().toStdString().length(),
                 hex_u2_pub, sizeof(hex_u2_pub));
    cesar_asym_decrypt(hex_u2_pub, sizeof(hex_u2_pub), key_session,
                        sizeof(key_session));

    // Encrypt message
    cast128_set_key(&cast_key, key_session, CAST_KEY_16);
    for (size_t i = 0; i < msg_size / 8; ++i) {
        cast128_crypt(&cast_key, (uint8_t *)&msg[i], CAST_ENCRYPT);
    }
    data_to_text((uint8_t *)msg, msg_size, text, text_size);
    ui->textEdit_encr_msg->setText((QString::fromStdString(string(text))));

    free(msg);
    free(text);
}

void MainWindow::on_pushButton_decr_clicked()
{
    cast_key_t cast_key;
    uint8_t hex_u2_pr[KEY_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t text_size;
    uint8_t signature[SIGN_SIZE];
    uint8_t key_session[KEY_SIZE];

    // Decrypt session
    text_to_data(ui->textEdit_sess_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_sess_key->toPlainText().toStdString().length(),
                 key_session, sizeof(key_session));
    text_to_data(ui->textEdit_u2_pr_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pr_key->toPlainText().toStdString().length(),
                 hex_u2_pr, sizeof(hex_u2_pr));
    cesar_asym_decrypt(hex_u2_pr, sizeof(hex_u2_pr), key_session,
                        sizeof(key_session));

    // Get message
    text_size = ui->textEdit_encr_msg->toPlainText().toStdString().length();
    msg_size = text_size / 2;
    msg = (char *)calloc(msg_size, 1);
    text = (char *)calloc(++text_size, 1);
    memcpy(text, ui->textEdit_encr_msg->toPlainText().toStdString().c_str(),
           text_size);
    text_to_data(text, text_size, (uint8_t*)msg, msg_size);

    // Decrypt message
    cast128_set_key(&cast_key, key_session, CAST_KEY_16);
    for (size_t i = 0; i < msg_size / 8; ++i) {
        cast128_crypt(&cast_key, (uint8_t *)&msg[i], CAST_DECRYPT);
    }
    data_to_text((uint8_t *)msg, msg_size, text, text_size);
    ui->textEdit_u2_msg->setText((QString::fromStdString(string(msg))));

    sha1_calculate(msg, msg_size, signature, sizeof(signature));

    free(msg);
    free(text);
}

void MainWindow::on_pushButton_validate_clicked()
{
    uint8_t hex_u1_pub[KEY_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t text_size;
    uint8_t signature[SIGN_SIZE];
    uint8_t signature2[SIGN_SIZE];

    // Get message
    msg_size = ui->textEdit_u2_msg->toPlainText().toStdString().length();
    text_size = (msg_size + 8) * 2 + 1;
    msg = (char *)calloc(msg_size + 8, 1);
    text = (char *)calloc(text_size, 1);
    memcpy(msg, ui->textEdit_u2_msg->toPlainText().toStdString().c_str(),
           msg_size);

    sha1_calculate(msg, msg_size, signature2, sizeof(signature2));

    // Decrypt signature
    text_to_data(ui->textEdit_dig_sign->toPlainText().toStdString().c_str(),
                 ui->textEdit_dig_sign->toPlainText().toStdString().length(),
                 signature, sizeof(signature));
    text_to_data(ui->textEdit_u1_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u1_pub_key->toPlainText().toStdString().length(),
                 hex_u1_pub, sizeof(hex_u1_pub));
    cesar_asym_decrypt(hex_u1_pub, sizeof(hex_u1_pub), signature,
                       sizeof(signature));

    if (memcmp(signature, signature2, SIGN_SIZE) != 0) {
        ui->label_validation_result->setText(
                       QString::fromStdString(string("Evenlope invalid")));
    } else {
        ui->label_validation_result->setText(
                       QString::fromStdString(string("Evenlope is valid")));
    }
}
