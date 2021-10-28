# Android-mdmClient-courseWork

안드로이드 클라이언트 개발을 위한 join guide 입니다. Android studio 를 기반으로 작성되었습니다.

### 1. Precondition

##### 1.1. Android studio 설치

21.09.23일 기준으로 아래 링크에서 다운로드 받아 설치합니다.

https://developer.android.com/studio

##### 1.2. Device 의 개발자모드 On

Device > 설정 > 디바이스 정보 > 소프트웨어 정보 > 빌드번호를 여러번 연타하면 개발자 옵션이 활성화됩니다. 뒤로 > 뒤로 > 개발자 옵션 > USB 디버깅을 On 으로 바꿔줍니다.

##### 1.3. ADB의 경로를 Path 환경변수에 추가

기본 경로는 아래입니다. cmd 콘솔에서 adb 를 쳤을 때 반응이 오도록 path 를 이어줍니다. <br>
(https://serendipper16.tistory.com/6 등 블로그를 참조합니다.)

C:\Users\사용자 이름\AppData\Local\Android\Sdk\platform-tools\

이후 기기를 개발용 PC와 연결하고, cmd 에서 adb devices 명령에 다음과 같이 반응하면 성공입니다.

C:\Users\Sungmin>adb devices <br>
*daemon not running; starting now at tcp:5037 <br>
*daemon started successfully <br>
List of devices attached <br>
5b42ccc6   device <br>
C:\Users\Sungmin>

### 2. Download

다음의 명령어를 쳐줍니다. (git이 설치되어 있어야 합니다. git 설치는 인터넷을 참고하세요.)

git clone로 파일을 다운로드할 곳을 소스경로로 지정하고, Git Bash에 아래의 코드를 입력합니다.

소스경로> git clone https://github.com/sungmin-net/android-mdmClient-courseWork.git

##### 2.1. Platform download

Prototype 은 여건상 마시멜로 버전으로 만들었습니다. 위에서 설치한 Android Studio를 열고 위쪽 메뉴의 Tools > SDK Manager 로 진입해서 Android 6.0 (Marshmallow) 에 체크 > Apply 를 눌러서 플랫폼을 다운로드 합니다.

### 3. Open

Android Studio > Open > 소스 경로 선택 > Ok 를 눌러줍니다. 처음 열었을 때는 Gradle project sync in progress... 하면서 시간이 상당히 소요될 수 있습니다.

### 4. Run

Alt + Shift + x 가 앱 빌드 + 설치 + 실행의 기본 단축키입니다. (File > Settings > Key map 에 들어가서, Windows 라고 설정되어 있는 단축키 스타일을 Eclipse 로 바꿔주면 좀 편합니다.) 파일을 open한 후 그 상태에서 바로 닽축기 입력을 하시면 됩니다. 시간이 조금 소요되며, 설치 완료 후 device에 앱을 확인하실 수 있고, 앱이 실행되어도, 앱이 Admin 이 아니므로 기기 제어를 할 수 없습니다.

##### 4.1. Admin 설정

Device 가 연결된 상태에서 cmd 콘솔에 다음의 adb 명령어를 쳐줍니다.

adb shell dpm set-device-owner net.sungmin.jicomsy/.AdminReceiver

다음과 같이 반응하면 성공입니다. (Device 안에 어떠한 Account 도 존재해서는 안됩니다. ex. 구글 계정)

C:\Users\Sungmin>adb shell dpm set-device-owner net.sungmin.jicomsy/.AdminReceiver <br>
Success: Device owner set to package net.sungmin.jicomsy <br>
Active admin set to component {net.sungmin.jicomsy/net.sungmin.jicomsy.AdminReceiver} <br>

C:\Users\Sungmin>

이 후, 다시 앱을 진입하면, REMOVE ADMIN 등의 버튼이 활성화되어 있습니다.

*참고로 개발용 PC와 device가 같은 네트워크(wifi)상에 있어야 모든 기능을 활용할 수 있습니다.

### 5. Upload

File > Export > Export to Zip file.. 로 진행하여 임의의 경로에 project 압축 파일을 떨어뜨리고, git clone 한 디렉토리에서 (중요) git pull 후, 수정한 파일을 복사하고 커밋을 생성하여 push 하는 것을 권장합니다.

### 6. Appendix

##### 6.1. Protocol

Client→Server: Magic + RsaEnc(Version + Cmd + UserId) + ServAlias

Client←Server: Magic + ToBeSigned(Version + TimeStamp + CurPolicies) + ServSign
