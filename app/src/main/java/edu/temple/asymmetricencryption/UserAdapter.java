package edu.temple.asymmetricencryption;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.ArrayList;

public class UserAdapter extends ArrayAdapter {
    private Context context;
    private ArrayList<User> userList;

    public UserAdapter(Context context, ArrayList<User> userList) {
        super(context, 0, userList);
        this.context = context;
        this.userList = userList;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View listItem = convertView;
        if(listItem == null) {
            listItem = (View) LayoutInflater.from(context).inflate(R.layout.list_item, parent, false);
        }

        User currentUser = userList.get(position);

        TextView usernameTextView = listItem.findViewById(R.id.listItemUsername);
        usernameTextView.setText(currentUser.getUsername());

        return listItem;
    }
}
