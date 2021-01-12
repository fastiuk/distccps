#include "mainwindow.h"
#include "ui_mainwindow.h"

extern "C" {
#include "cast128.h"
#include "cesar.h"
#include "sha.h"
}

#define ASYM_KEY_SIZE   16

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

static __attribute__((unused)) void print_bytes(const char *header,
                                                uint8_t *data, size_t size)
{
    printf("%s: ", header);
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx", data[i]);
    }
    printf("\n");
}

static int text_to_data(const char *text, size_t tsize, uint8_t *data,
                        size_t dsize)
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

void MainWindow::on_pushButton_gen_keys_clicked()
{
    uint8_t key_data[ASYM_KEY_SIZE];
    char key_text[ASYM_KEY_SIZE * 2 + 1];

    // Generate keys for u1
    cesar_keygen(key_data, sizeof(key_data));
    data_to_text(key_data, sizeof(key_data), key_text, sizeof(key_text));
    ui->textEdit_u1_pr_key->setText(QString::fromStdString(string(key_text)));
    cesar_shuffle_key(key_data, sizeof(key_data));
    data_to_text(key_data, sizeof(key_data), key_text, sizeof(key_text));
    ui->textEdit_u1_pub_key->setText(QString::fromStdString(string(key_text)));

    // Generate keys for u2
    cesar_keygen(key_data, sizeof(key_data));
    data_to_text(key_data, sizeof(key_data), key_text, sizeof(key_text));
    ui->textEdit_u2_pr_key->setText(QString::fromStdString(string(key_text)));
    cesar_shuffle_key(key_data, sizeof(key_data));
    data_to_text(key_data, sizeof(key_data), key_text, sizeof(key_text));
    ui->textEdit_u2_pub_key->setText(QString::fromStdString(string(key_text)));
}

void MainWindow::on_pushButton_gen_sess_key_clicked()
{
    uint8_t session_key_data[ASYM_KEY_SIZE];
    char session_key_text[ASYM_KEY_SIZE * 2 + 1];
    uint8_t u2_pub_key_data[ASYM_KEY_SIZE];

    // Generate session key
    for (size_t i = 0; i < ASYM_KEY_SIZE; ++i) {
        session_key_data[i] = rand() % 256;
    }

    // Encrypt session key
    text_to_data(ui->textEdit_u2_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pub_key->toPlainText().toStdString().length(),
                 u2_pub_key_data, sizeof(u2_pub_key_data));
    cesar_encrypt(u2_pub_key_data, sizeof(u2_pub_key_data), session_key_data,
                  sizeof(session_key_data));
    data_to_text(session_key_data, sizeof(session_key_data), session_key_text,
                 sizeof(session_key_text));
    ui->textEdit_sess_key->setText(QString::fromStdString(string(
                                                            session_key_text)));
}

void MainWindow::on_pushButton_encr_clicked()
{
    cast_key_t cast_key;
    uint8_t u1_pr_key_data[ASYM_KEY_SIZE];
    uint8_t u2_pub_key_data[ASYM_KEY_SIZE];
    uint8_t signature_data[SHASUM_SIZE];
    char signature_text[SHASUM_SIZE * 2 + 1];
    uint8_t session_key_data[ASYM_KEY_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t msg_blocks;
    size_t text_size;

    // Get message
    msg_size = ui->textEdit_u1_msg->toPlainText().toStdString().length();
    msg_blocks = msg_size / 8;
    msg_blocks += msg_size % 8 ? 1 : 0;
    text_size = msg_blocks * 8 * 2 + 1;
    msg = (char *)calloc(msg_blocks * 8, 1);
    text = (char *)calloc(text_size, 1);
    memcpy(msg, ui->textEdit_u1_msg->toPlainText().toStdString().c_str(),
           msg_size);

    // Encrypt digital signature
    sha1_calculate(msg, msg_size, signature_data, sizeof(signature_data));
    text_to_data(ui->textEdit_u1_pr_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u1_pr_key->toPlainText().toStdString().length(),
                 u1_pr_key_data, sizeof(u1_pr_key_data));
    cesar_encrypt(u1_pr_key_data, sizeof(u1_pr_key_data), signature_data,
                  sizeof(signature_data));
    data_to_text(signature_data, sizeof(signature_data), signature_text,
                 sizeof(signature_text));
    ui->textEdit_dig_sign->setText(QString::fromStdString(string(
                                                              signature_text)));

    // Decrypt session key
    text_to_data(ui->textEdit_sess_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_sess_key->toPlainText().toStdString().length(),
                 session_key_data, sizeof(session_key_data));
    text_to_data(ui->textEdit_u2_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pub_key->toPlainText().toStdString().length(),
                 u2_pub_key_data, sizeof(u2_pub_key_data));
    cesar_decrypt(u2_pub_key_data, sizeof(u2_pub_key_data), session_key_data,
                  sizeof(session_key_data));

    // Encrypt message
    cast128_set_key(&cast_key, session_key_data, CAST_KEY_16);
    for (size_t i = 0; i < msg_blocks; ++i) {
        cast128_crypt(&cast_key, (uint8_t *)&msg[i * 8], CAST_ENCRYPT);
    }
    data_to_text((uint8_t *)msg, msg_blocks * 8, text, text_size);
    ui->textEdit_encr_msg->setText((QString::fromStdString(string(text))));

    free(msg);
    free(text);
}

void MainWindow::on_pushButton_decr_clicked()
{
    cast_key_t cast_key;
    uint8_t u2_pr_key_data[ASYM_KEY_SIZE];
    uint8_t session_key_data[ASYM_KEY_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t msg_blocks;
    size_t text_size;

    // Decrypt session kry
    text_to_data(ui->textEdit_sess_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_sess_key->toPlainText().toStdString().length(),
                 session_key_data, sizeof(session_key_data));
    text_to_data(ui->textEdit_u2_pr_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u2_pr_key->toPlainText().toStdString().length(),
                 u2_pr_key_data, sizeof(u2_pr_key_data));
    cesar_decrypt(u2_pr_key_data, sizeof(u2_pr_key_data), session_key_data,
                  sizeof(session_key_data));

    // Get message
    text_size = ui->textEdit_encr_msg->toPlainText().toStdString().length();
    msg_blocks = text_size / 2 / 8;
    msg_size = msg_blocks * 8 + 1;
    msg = (char *)calloc(msg_size, 1);
    text = (char *)calloc(++text_size, 1);
    memcpy(text, ui->textEdit_encr_msg->toPlainText().toStdString().c_str(),
           text_size);
    text_to_data(text, text_size, (uint8_t*)msg, msg_size);

    // Decrypt message
    cast128_set_key(&cast_key, session_key_data, CAST_KEY_16);
    for (size_t i = 0; i < msg_blocks; ++i) {
        cast128_crypt(&cast_key, (uint8_t *)&msg[i * 8], CAST_DECRYPT);
    }
    ui->textEdit_u2_msg->setText((QString::fromStdString(string(msg))));

    free(msg);
    free(text);
}

void MainWindow::on_pushButton_validate_clicked()
{
    uint8_t u1_pub_key[ASYM_KEY_SIZE];
    uint8_t signature[SHASUM_SIZE];
    uint8_t signature2[SHASUM_SIZE];
    char *msg;
    char *text;
    size_t msg_size;
    size_t msg_blocks;
    size_t text_size;

    // Get message
    msg_size = ui->textEdit_u2_msg->toPlainText().toStdString().length();
    msg_blocks = msg_size / 8;
    msg_blocks += msg_size % 8 ? 1 : 0;
    text_size = msg_blocks * 8 * 2 + 1;
    msg = (char *)calloc(msg_blocks * 8, 1);
    text = (char *)calloc(text_size, 1);
    memcpy(msg, ui->textEdit_u2_msg->toPlainText().toStdString().c_str(),
           msg_size);

    // Calculate signature
    sha1_calculate(msg, msg_size, signature, sizeof(signature));

    // Decrypt digital signature
    text_to_data(ui->textEdit_dig_sign->toPlainText().toStdString().c_str(),
                 ui->textEdit_dig_sign->toPlainText().toStdString().length(),
                 signature2, sizeof(signature2));
    text_to_data(ui->textEdit_u1_pub_key->toPlainText().toStdString().c_str(),
                 ui->textEdit_u1_pub_key->toPlainText().toStdString().length(),
                 u1_pub_key, sizeof(u1_pub_key));
    cesar_decrypt(u1_pub_key, sizeof(u1_pub_key), signature2,
                       sizeof(signature2));

    // Compare signatures
    if (memcmp(signature, signature2, SHASUM_SIZE) != 0) {
        ui->label_validation_result->setText(
                       QString::fromStdString(string("Evelope invalid")));
    } else {
        ui->label_validation_result->setText(
                       QString::fromStdString(string("Evelope is valid")));
    }
}
