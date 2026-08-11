import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

// qmllint disable import
import passkeyd.ui.selection

Kirigami.ApplicationWindow {
    id: root
    visible: true
    title: authState.title

    width: 420
    height: 160
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height

    flags: Qt.Dialog | Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint

    onClosing: close => {
        close.accepted = false;
        authState.deny();
    }

    AuthorizationState {
        id: authState
    }

    pageStack.initialPage: Kirigami.Page {
        title: authState.title

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.smallSpacing * 1.5
            spacing: Kirigami.Units.smallSpacing

            Controls.Label {
                text: authState.description
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                font.pointSize: 9.5
            }

            Item {
                Layout.fillHeight: true
            }

            RowLayout {
                Layout.alignment: Qt.AlignRight
                Layout.topMargin: Kirigami.Units.smallSpacing
                spacing: Kirigami.Units.smallSpacing

                Controls.Button {
                    text: authState.buttonText
                    highlighted: true
                    onClicked: authState.authorize()
                    Kirigami.Theme.colorSet: Kirigami.Theme.Button
                }
            }
        }
    }
}
