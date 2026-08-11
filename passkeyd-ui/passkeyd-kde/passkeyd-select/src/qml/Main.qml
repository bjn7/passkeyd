import QtQuick
import QtQuick.Layouts
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

// qmllint disable import
import passkeyd.ui.select

Kirigami.ApplicationWindow {
    id: root
    visible: true
    title: selectionState.skipSelection ? selectionState.authTitle : selectionState.selectTitle

    width: 420
    height: 230
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height

    flags: Qt.Dialog | Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint

    onClosing: close => {
        close.accepted = false;
        selectionState.deny();
    }

    SelectionState {
        id: selectionState
    }

    pageStack.initialPage: selectionState.skipSelection ? authorizePage : selectPage

    Item {
        id: pagePool
        anchors.fill: parent
        visible: false

        Kirigami.Page {
            id: selectPage
            title: selectionState.selectTitle

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Kirigami.Units.smallSpacing * 1.5
                spacing: Kirigami.Units.mediumSpacing

                Controls.Label {
                    text: selectionState.selectDesc
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    font.pointSize: 9.5
                }

                Controls.Frame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(accountList.contentHeight + 4, 38 * 3)
                    Layout.maximumHeight: 38 * 3
                    padding: 0

                    ListView {
                        id: accountList
                        anchors.fill: parent
                        model: selectionState.accounts
                        clip: true

                        delegate: Controls.ItemDelegate {
                            width: accountList.width
                            height: 38
                            text: modelData
                            icon.name: "user-identity"

                            onClicked: {
                                selectionState.selectAccount(index);
                                root.pageStack.replace(authorizePage);
                            }
                        }
                    }
                }

                Item {
                    Layout.fillHeight: true
                }
            }
        }

        Kirigami.Page {
            id: authorizePage
            title: selectionState.authTitle

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Kirigami.Units.smallSpacing * 1.5
                spacing: Kirigami.Units.mediumSpacing

                Controls.Label {
                    text: selectionState.authDesc
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    font.pointSize: 9.5
                }

                Controls.TextField {
                    id: passwordField
                    Layout.fillWidth: true
                    echoMode: TextInput.Password
                    placeholderText: qsTr("Password")
                    onAccepted: authorizePage.submitPassword()

                    onVisibleChanged: {
                        if (visible) {
                            forceActiveFocus();
                        }
                    }
                }

                Controls.Label {
                    text: selectionState.authHelper
                    color: Kirigami.Theme.negativeTextColor
                    visible: selectionState.isInvalid
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }

                Item {
                    Layout.fillHeight: true
                }

                RowLayout {
                    Layout.alignment: Qt.AlignRight
                    Layout.topMargin: Kirigami.Units.smallSpacing
                    spacing: Kirigami.Units.smallSpacing

                    Controls.Button {
                        text: qsTr("Authorize")
                        highlighted: true
                        onClicked: authorizePage.submitPassword()
                        Kirigami.Theme.colorSet: Kirigami.Theme.Button
                    }
                }
            }

            function submitPassword() {
                if (passwordField.text) {
                    selectionState.authorize(passwordField.text);
                    passwordField.text = "";
                }
            }
        }
    }
}
