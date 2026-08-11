import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

// qmllint disable import
import passkeyd.ui.enroll

Kirigami.ApplicationWindow {
    id: root
    visible: true

    title: authState.title

    width: 420
    height: 210
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height

    flags: Qt.Dialog | Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint

    onClosing: (closeEvent) => {
        closeEvent.accepted = false;
        authState.deny();
    }

    AuthorizationState {
        id: authState
    }

    pageStack.initialPage: Kirigami.Page {
        title: authState.title

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.largeSpacing

            Controls.Label {
                Layout.fillWidth: true
                text: authState.description
                wrapMode: Text.WordWrap
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                rowSpacing: Kirigami.Units.smallSpacing
                columnSpacing: Kirigami.Units.largeSpacing

                Controls.Label {
                    text: "Site:"
                    font.bold: true
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: authState.siteId
                    elide: Text.ElideRight
                }

                Controls.Label {
                    text: "Name:"
                    font.bold: true
                    visible: !!authState.userName
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: authState.userName
                    elide: Text.ElideRight
                    visible: !!authState.userName
                }
            }

            Item {
                Layout.fillHeight: true
            }

            Controls.Button {
                Layout.alignment: Qt.AlignRight | Qt.AlignBottom
                text: authState.buttonText
                highlighted: true
                Kirigami.Theme.colorSet: Kirigami.Theme.Button

                onClicked: {
                    authState.authorize();
                }
            }
        }
    }
}
