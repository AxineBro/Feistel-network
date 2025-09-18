#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QUrl>
#include <QFileInfo>
#include <QDebug>
#include <QFile>
#include <QMenu>
#include <QDir>
#include <QDateTime>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    setAcceptDrops(true);
    ui->statusLabel->setText("");
    ui->decryptStatusLabel->setText("");
    ui->fileList->setViewMode(QListView::ListMode);
    ui->fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ui->fileList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->fileList, &QListWidget::customContextMenuRequested, this, &MainWindow::showFileListContextMenu);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
    if (event->mimeData()->hasUrls() && ui->tabWidget->currentIndex() == 0) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void MainWindow::dragMoveEvent(QDragMoveEvent *event) {
    if (event->mimeData()->hasUrls() && ui->tabWidget->currentIndex() == 0) {
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void MainWindow::dropEvent(QDropEvent *event) {
    if (ui->tabWidget->currentIndex() == 0 && event->mimeData()->hasUrls()) {
        foreach (const QUrl &url, event->mimeData()->urls()) {
            QString filePath = url.toLocalFile();
            if (!filePath.isEmpty()) {
                selectedFiles.push_back(filePath);
                ui->fileList->addItem(QFileInfo(filePath).fileName());
                qDebug() << "Added file:" << filePath;
            }
        }
        ui->statusLabel->setText(QString("Added %1 files").arg(ui->fileList->count()));
        event->acceptProposedAction();
    } else {
        event->ignore();
    }
}

void MainWindow::on_addFilesButton_clicked() {
    QStringList files = QFileDialog::getOpenFileNames(this, "Select Files to Encrypt", "", "All Files (*.*)");
    if (!files.isEmpty()) {
        for (const QString& file : files) {
            selectedFiles.push_back(file);
            ui->fileList->addItem(QFileInfo(file).fileName());
            qDebug() << "Added file via dialog:" << file;
        }
        ui->statusLabel->setText(QString("Added %1 files").arg(files.size()));
    }
}

void MainWindow::on_removeButton_clicked() {
    QList<QListWidgetItem*> selectedItems = ui->fileList->selectedItems();
    if (selectedItems.isEmpty()) {
        ui->statusLabel->setText("No files selected to remove!");
        return;
    }
    for (QListWidgetItem* item : selectedItems) {
        int index = ui->fileList->row(item);
        selectedFiles.erase(selectedFiles.begin() + index);
        delete item;
    }
    ui->statusLabel->setText(QString("%1 files in list").arg(ui->fileList->count()));
}

void MainWindow::on_clearButton_clicked() {
    selectedFiles.clear();
    ui->fileList->clear();
    ui->statusLabel->setText("List cleared");
}

void MainWindow::on_encryptButton_clicked() {
    if (selectedFiles.empty()) {
        ui->statusLabel->setText("No files selected!");
        return;
    }

    QString baseDir = QFileDialog::getExistingDirectory(this, "Select Output Directory", "");
    if (baseDir.isEmpty()) {
        ui->statusLabel->setText("No directory selected!");
        return;
    }

    QString outputDir = create_unique_directory(baseDir);
    if (outputDir.isEmpty()) {
        ui->statusLabel->setText("Failed to create output directory!");
        return;
    }

    uint64_t key = crypto.generate_key();
    QString keyHex = QString("%1").arg(key, 16, 16, QChar('0')).toUpper();

    QString keyFile = outputDir + "/encryption_key.key";
    QFile keyOut(keyFile);
    if (!keyOut.open(QIODevice::WriteOnly | QIODevice::Text)) {
        ui->statusLabel->setText("Failed to save key file!");
        return;
    }
    QTextStream keyStream(&keyOut);
    keyStream << keyHex;
    keyOut.close();

    int successCount = 0;
    for (const QString& filePath : selectedFiles) {
        QString outputFile = outputDir + "/" + QFileInfo(filePath).fileName() + ".axine";
        try {
            crypto.process_encrypt_file(filePath, outputFile, key);
            successCount++;
        } catch (const std::exception& e) {
            ui->statusLabel->setText(QString("Error encrypting %1: %2").arg(QFileInfo(filePath).fileName(), e.what()));
            return;
        }
    }

    ui->statusLabel->setText(QString("Encrypted %1 files. Key: %2").arg(successCount).arg(keyHex));
    selectedFiles.clear();
    ui->fileList->clear();
}

void MainWindow::on_browseButton_clicked() {
    QString file = QFileDialog::getOpenFileName(this, "Select Encrypted File", "", "Axine Files (*.axine)");
    if (!file.isEmpty()) {
        ui->encryptedFilePath->setText(file);
    }
}

void MainWindow::on_browseKeyButton_clicked() {
    QString keyFile = QFileDialog::getOpenFileName(this, "Select Key File", "", "Key Files (*.key)");
    if (!keyFile.isEmpty()) {
        QFile file(keyFile);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString key = QString(file.readAll()).trimmed();
            ui->keyInput->setText(key);
            file.close();
        } else {
            ui->decryptStatusLabel->setText("Failed to read key file!");
        }
    }
}

void MainWindow::on_decryptButton_clicked() {
    QString inputFile = ui->encryptedFilePath->text();
    QString keyStr = ui->keyInput->text();
    if (inputFile.isEmpty() || keyStr.isEmpty()) {
        ui->decryptStatusLabel->setText("Missing file or key!");
        return;
    }

    uint64_t key = crypto.parse_key(keyStr);
    if (key == 0) {
        ui->decryptStatusLabel->setText("Invalid key format! Use 16 hex chars.");
        return;
    }

    QString baseDir = QFileDialog::getExistingDirectory(this, "Select Output Directory", "");
    if (baseDir.isEmpty()) {
        ui->decryptStatusLabel->setText("No directory selected!");
        return;
    }

    QString outputDir = create_unique_directory(baseDir);
    if (outputDir.isEmpty()) {
        ui->decryptStatusLabel->setText("Failed to create output directory!");
        return;
    }

    QString outputFile = outputDir + "/" + QFileInfo(inputFile).completeBaseName();
    try {
        crypto.process_decrypt_file(inputFile, outputFile, key);
        ui->decryptStatusLabel->setText(QString("Decrypted to %1").arg(outputFile));
    } catch (const std::exception& e) {
        ui->decryptStatusLabel->setText(QString("Error decrypting: %1").arg(e.what()));
    }
}

void MainWindow::showFileListContextMenu(const QPoint &pos) {
    QMenu contextMenu("Context menu", ui->fileList);
    QAction action("Remove", this);
    connect(&action, &QAction::triggered, this, [&]() {
        QList<QListWidgetItem*> selectedItems = ui->fileList->selectedItems();
        if (selectedItems.isEmpty()) {
            ui->statusLabel->setText("No files selected to remove!");
            return;
        }
        for (QListWidgetItem* item : selectedItems) {
            int index = ui->fileList->row(item);
            selectedFiles.erase(selectedFiles.begin() + index);
            delete item;
        }
        ui->statusLabel->setText(QString("%1 files in list").arg(ui->fileList->count()));
    });
    contextMenu.addAction(&action);
    contextMenu.exec(ui->fileList->mapToGlobal(pos));
}

QString MainWindow::create_unique_directory(const QString& basePath) {
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    QString uniqueDir = basePath + "/Encrypted_" + timestamp;
    QDir dir;
    if (!dir.exists(uniqueDir) && !dir.mkpath(uniqueDir)) {
        return "";
    }
    return uniqueDir;
}
