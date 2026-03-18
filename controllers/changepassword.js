const bcrypt = require('bcrypt');
const User = require('../models/User'); // Giả sử bạn có mô hình User
const authenticate = require('../middlewares/authenticate'); // Middleware xác thực người dùng

// API ChangePassword
exports.changePassword = async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Kiểm tra tính hợp lệ của mật khẩu mới (dài hơn 6 ký tự)
    if (newPassword.length < 6) {
        return res.status(400).send('Mật khẩu mới phải dài hơn 6 ký tự');
    }

    try {
        // Lấy thông tin người dùng từ token
        const user = await User.findById(req.user.id); // req.user.id được lấy từ token

        // So sánh mật khẩu cũ với mật khẩu trong cơ sở dữ liệu
        const isMatch = await bcrypt.compare(oldPassword, user.password);

        if (!isMatch) {
            return res.status(400).send('Mật khẩu cũ không đúng');
        }

        // Mã hóa mật khẩu mới
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Cập nhật mật khẩu mới vào cơ sở dữ liệu
        user.password = hashedPassword;
        await user.save();

        res.send('Mật khẩu đã được thay đổi thành công');
    } catch (error) {
        console.error(error);
        res.status(500).send('Lỗi hệ thống');
    }
};