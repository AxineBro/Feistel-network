#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDropEvent>
#include <QMimeData>
#include <vector>
#include "cryptoprocessor.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dragMoveEvent(QDragMoveEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void on_addFilesButton_clicked();
    void on_removeButton_clicked();
    void on_clearButton_clicked();
    void on_encryptButton_clicked();
    void on_browseButton_clicked();
    void on_browseKeyButton_clicked();
    void on_decryptButton_clicked();
    void showFileListContextMenu(const QPoint &pos);

private:
    Ui::MainWindow *ui;
    std::vector<QString> selectedFiles;
    CryptoProcessor crypto; // Экземпляр CryptoProcessor
    QString create_unique_directory(const QString& basePath);
};

#endif
